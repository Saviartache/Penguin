//! Датаграммы внутри потока.
//!
//! # Один поток на всю сессию
//!
//! Адрес назначения стоит на каждой посылке ([`crate::frame::udp`]), поэтому
//! один поток обслуживает всю UDP-сессию приложения, сколько бы адресатов у
//! неё ни было. Это дешевле, чем у SOCKS5: там на датаграммы открывается ещё
//! и отдельный сокет, а здесь всё идёт по тому же соединению TLS.
//!
//! # Почему половины под замками
//!
//! [`ProxyDatagram`] принимает `&self`: один канал обслуживает и отправку, и
//! приём, и зовут их разные задачи одновременно. Поток же принадлежит одной
//! задаче — [`ProxyStream`] намеренно не `Sync`.
//!
//! Поэтому поток делится надвое и каждая половина кладётся под свой замок.
//! Два замка, а не один: с одним чтение держало бы отправку всё время, пока
//! ждёт следующую датаграмму, — то есть всегда.
//!
//! Замки асинхронные: под ними ждут ввод-вывод, а обычный `Mutex`, взятый
//! через `.await`, блокирует исполнителя целиком.

use bytes::BytesMut;
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
    send: Mutex<WriteHalf<Box<dyn ProxyStream>>>,
    recv: Mutex<Incoming>,
}

/// Читающая половина вместе с тем, что уже прочитано, но ещё не разобрано.
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
            send: Mutex::new(send),
            recv: Mutex::new(Incoming {
                io,
                buffer: BytesMut::with_capacity(CHUNK),
            }),
        }
    }
}

#[async_trait::async_trait]
impl ProxyDatagram for TrojanDatagram {
    async fn send_to(
        &self,
        payload: bytes::Bytes,
        target: &SocketAddress,
    ) -> Result<(), ProtocolError> {
        let frame = udp::encode(target, &payload).map_err(ProtocolError::from)?;

        let mut send = self.send.lock().await;
        // Одной записью: заголовок и данные, разъехавшиеся по разным пакетам,
        // сервер соберёт, но по дороге они выглядят иначе, чем один пакет.
        send.write_all(&frame).await?;
        send.flush().await?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(bytes::Bytes, SocketAddress), ProtocolError> {
        let mut guard = self.recv.lock().await;
        // Половинки берутся врозь: читающая занимает буфер, и одолжить его
        // ей вместе с сокетом одним заимствованием нельзя.
        let Incoming { io, buffer } = &mut *guard;

        loop {
            if let Some((source, payload, used)) =
                udp::decode(buffer).map_err(ProtocolError::from)?
            {
                let _ = buffer.split_to(used);
                return Ok((payload, source));
            }

            let before = buffer.len();
            buffer.resize(before + CHUNK, 0);
            let read = io.read(&mut buffer[before..]).await?;
            buffer.truncate(before + read);

            if read == 0 {
                // Конец потока посреди датаграммы — это потерянные данные, а
                // не тишина: приложение иначе примет обрывок за полный ответ.
                return Err(TrojanError::Disconnected(if before == 0 {
                    "сервер закрыл канал датаграмм".to_owned()
                } else {
                    "сервер оборвал датаграмму на середине".to_owned()
                })
                .into());
            }
        }
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        let mut send = self.send.lock().await;
        send.shutdown().await?;
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
        // Внутри TLS границ нет: сервер вправе прислать обе одним куском.
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
        // Обрывок, отданный приложением за полный ответ, хуже потери.
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
