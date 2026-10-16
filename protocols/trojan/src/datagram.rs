//! Датаграммы внутри потока: один поток на всю UDP-сессию (адрес стоит на каждой посылке).
//!
//! `ProxyDatagram` работает через `&self`, поэтому поток делится надвое под двумя
//! асинхронными замками: с одним чтение держало бы отправку.

use bytes::{Bytes, BytesMut};
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_proto::stream::ProxyStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use crate::error::TrojanError;
use crate::frame::udp;

/// Сколько байт брать из потока за раз.
const CHUNK: usize = 16 * 1024;

/// Канал датаграмм поверх потока Trojan.
pub struct TrojanDatagram {
    send: Mutex<Outgoing>,
    recv: Mutex<Incoming>,
}

/// Пишущая половина и буфер сборки кадра.
struct Outgoing {
    io: WriteHalf<Box<dyn ProxyStream>>,
    frame: Vec<u8>,
}

/// Читающая половина и прочитанное, но не разобранное.
struct Incoming {
    io: ReadHalf<Box<dyn ProxyStream>>,
    buffer: BytesMut,
}

impl std::fmt::Debug for TrojanDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrojanDatagram").finish()
    }
}

impl TrojanDatagram {
    /// Собирает канал вокруг потока, по которому уже ушёл заголовок `UDP`.
    pub fn new(stream: Box<dyn ProxyStream>) -> Self {
        let (io, send) = tokio::io::split(stream);
        Self {
            send: Mutex::new(Outgoing {
                io: send,
                frame: Vec::new(),
            }),
            recv: Mutex::new(Incoming {
                io,
                buffer: BytesMut::with_capacity(CHUNK),
            }),
        }
    }
}

#[async_trait::async_trait]
impl ProxyDatagram for TrojanDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let mut guard = self.send.lock().await;
        let Outgoing { io, frame } = &mut *guard;

        // Одной записью, как один пакет
        frame.clear();
        udp::encode_into(frame, target, &payload).map_err(ProtocolError::from)?;
        io.write_all(frame).await?;
        io.flush().await?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let mut guard = self.recv.lock().await;
        let Incoming { io, buffer } = &mut *guard;

        loop {
            if let Some((source, range)) = udp::decode(buffer).map_err(ProtocolError::from)? {
                let mut frame = buffer.split_to(range.end);
                return Ok((frame.split_off(range.start).freeze(), source));
            }

            let had_data = !buffer.is_empty();
            buffer.reserve(CHUNK);
            if io.read_buf(buffer).await? == 0 {
                // Обрыв посреди датаграммы — потеря, не тишина
                return Err(TrojanError::Disconnected(if !had_data {
                    "сервер закрыл канал датаграмм".to_owned()
                } else {
                    "сервер оборвал датаграмму на середине".to_owned()
                })
                .into());
            }
        }
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.send.lock().await.io.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    fn target(port: u16) -> SocketAddress {
        SocketAddress::ip("203.0.113.5".parse().expect("адрес"), port)
    }

    #[tokio::test]
    async fn a_datagram_goes_out_the_way_the_protocol_says() {
        let (client, mut server) = duplex(4096);
        let channel = TrojanDatagram::new(Box::new(client));

        channel
            .send_to(Bytes::from_static("вопрос".as_bytes()), &target(53))
            .await
            .expect("ушло");

        let expected = udp::encode(&target(53), "вопрос".as_bytes()).expect("собирается");
        let mut got = vec![0u8; expected.len()];
        server.read_exact(&mut got).await.expect("пришло");
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn two_datagrams_in_one_chunk_are_read_one_by_one() {
        let (client, mut server) = duplex(4096);
        let channel = TrojanDatagram::new(Box::new(client));

        let mut wire = udp::encode(&target(53), b"one").expect("собирается");
        wire.extend_from_slice(&udp::encode(&target(5353), b"two").expect("собирается"));
        server.write_all(&wire).await.expect("ушло");

        let (payload, source) = channel.recv_from().await.expect("пришло");
        assert_eq!(&payload[..], b"one");
        assert_eq!(source, target(53));

        let (payload, source) = channel.recv_from().await.expect("пришло");
        assert_eq!(&payload[..], b"two");
        assert_eq!(source, target(5353));
    }

    #[tokio::test]
    async fn a_datagram_split_across_packets_is_assembled() {
        let (client, mut server) = duplex(4096);
        let channel = TrojanDatagram::new(Box::new(client));

        let wire = udp::encode(&target(53), b"payload").expect("собирается");
        let (head, tail) = wire.split_at(5);
        server.write_all(head).await.expect("ушло");

        let reader = tokio::spawn(async move { channel.recv_from().await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        server.write_all(tail).await.expect("ушло");

        let (payload, _) = reader.await.expect("задача").expect("пришло");
        assert_eq!(&payload[..], b"payload");
    }

    #[tokio::test]
    async fn a_stream_cut_mid_datagram_is_an_error() {
        let (client, mut server) = duplex(4096);
        let channel = TrojanDatagram::new(Box::new(client));

        let wire = udp::encode(&target(53), b"payload").expect("собирается");
        server.write_all(&wire[..6]).await.expect("ушло");
        drop(server);

        let err = channel.recv_from().await.expect_err("оборвано");
        assert!(err.to_string().contains("середине"), "{err}");
    }

    #[tokio::test]
    async fn a_clean_close_is_told_apart_from_a_cut() {
        let (client, server) = duplex(4096);
        let channel = TrojanDatagram::new(Box::new(client));
        drop(server);

        let err = channel.recv_from().await.expect_err("канал закрыт");
        assert!(err.to_string().contains("закрыл канал"), "{err}");
    }
}
