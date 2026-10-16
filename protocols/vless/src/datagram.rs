//! Канал датаграмм: поток на адресата (адрес назван один раз, в заголовке).
//!
//! `send_to(X)` пишет в поток X; задача чтения каждого потока кладёт ответы с адресом потока в
//! общую очередь для `recv_from`. Потоки живут до закрытия канала, их число ограничено
//! [`MAX_SESSIONS`].

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_proto::stream::ProxyStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::connector::Connector;
use crate::error::VlessError;
use crate::frame::request::CMD_UDP;
use crate::frame::udp;

/// Сколько адресатов канал держит одновременно: у каждого свой сокет, TLS и задача.
pub const MAX_SESSIONS: usize = 256;

/// Сколько ответов держать в очереди, пока их не забрали.
const QUEUE: usize = 512;

/// Сколько байт брать из потока за раз.
const CHUNK: usize = 16 * 1024;

/// Канал датаграмм через сервер VLESS.
pub struct VlessDatagram {
    connector: Arc<Connector>,
    sessions: Mutex<HashMap<SocketAddress, Session>>,
    /// Ответы со всех потоков.
    incoming: Mutex<mpsc::Receiver<(Bytes, SocketAddress)>>,
    sender: mpsc::Sender<(Bytes, SocketAddress)>,
}

/// Один адресат.
struct Session {
    send: WriteHalf<Box<dyn ProxyStream>>,
    reader: JoinHandle<()>,
}

impl std::fmt::Debug for VlessDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessDatagram")
            .field("connector", &self.connector)
            .finish()
    }
}

impl VlessDatagram {
    /// Потоки открывает первая посылка каждому адресату.
    pub fn new(connector: Arc<Connector>) -> Self {
        let (sender, incoming) = mpsc::channel(QUEUE);
        Self {
            connector,
            sessions: Mutex::new(HashMap::new()),
            incoming: Mutex::new(incoming),
            sender,
        }
    }
}

#[async_trait]
impl ProxyDatagram for VlessDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let frame = udp::encode(&payload).map_err(ProtocolError::from)?;
        let mut sessions = self.sessions.lock().await;

        if !sessions.contains_key(target) {
            if sessions.len() >= MAX_SESSIONS {
                return Err(ProtocolError::Unsupported(
                    "больше адресатов в одном канале VLESS не помещается",
                ));
            }

            let io = self.connector.open(CMD_UDP, target).await?;
            let (recv, send) = tokio::io::split(io);
            let reader = tokio::spawn(read_replies(recv, target.clone(), self.sender.clone()));
            sessions.insert(target.clone(), Session { send, reader });
        }

        let Some(session) = sessions.get_mut(target) else {
            return Err(VlessError::Disconnected("поток до адресата пропал".into()).into());
        };

        // Обрыв адресата убирает только его поток.
        if let Err(err) = write_frame(&mut session.send, &frame).await {
            if let Some(session) = sessions.remove(target) {
                session.reader.abort();
            }
            return Err(err.into());
        }
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let mut incoming = self.incoming.lock().await;
        incoming
            .recv()
            .await
            .ok_or_else(|| VlessError::Disconnected("канал датаграмм закрыт".to_owned()).into())
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        let mut sessions = self.sessions.lock().await;
        for (_, mut session) in sessions.drain() {
            session.reader.abort();
            let _ = session.send.shutdown().await;
        }
        Ok(())
    }
}

impl Drop for VlessDatagram {
    fn drop(&mut self) {
        if let Ok(sessions) = self.sessions.try_lock() {
            for session in sessions.values() {
                session.reader.abort();
            }
        }
    }
}

/// Пишет кадр в поток адресата.
async fn write_frame(
    send: &mut WriteHalf<Box<dyn ProxyStream>>,
    frame: &[u8],
) -> Result<(), VlessError> {
    send.write_all(frame).await?;
    send.flush().await?;
    Ok(())
}

/// Читает ответы одного адресата в общую очередь; кончается с потоком или очередью.
async fn read_replies(
    mut io: ReadHalf<Box<dyn ProxyStream>>,
    source: SocketAddress,
    sender: mpsc::Sender<(Bytes, SocketAddress)>,
) {
    let mut buffer = BytesMut::with_capacity(CHUNK);

    loop {
        match udp::decode(&buffer) {
            Ok(Some((payload, used))) => {
                let _ = buffer.split_to(used);
                if sender.send((payload, source.clone())).await.is_err() {
                    return;
                }
                continue;
            }
            Ok(None) => {}
            Err(err) => {
                tracing::debug!(%source, %err, "поток датаграмм разъехался");
                return;
            }
        }

        let before = buffer.len();
        buffer.resize(before + CHUNK, 0);
        let read = match io.read(&mut buffer[before..]).await {
            Ok(read) => read,
            Err(err) => {
                tracing::debug!(%source, %err, "поток датаграмм оборвался");
                return;
            }
        };
        buffer.truncate(before + read);

        if read == 0 {
            tracing::debug!(%source, "поток датаграмм закрыт сервером");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replies_carry_the_address_of_the_stream_they_came_from() {
        let (client, mut server) = tokio::io::duplex(4096);
        let (sender, mut incoming) = mpsc::channel(8);
        let source = SocketAddress::domain("dns.example.com", 53);

        let boxed: Box<dyn ProxyStream> = Box::new(client);
        let (recv, _send) = tokio::io::split(boxed);
        let reader = tokio::spawn(read_replies(recv, source.clone(), sender));

        server
            .write_all(&udp::encode(b"answer").expect("собирается"))
            .await
            .expect("ушло");

        let (payload, from) = incoming.recv().await.expect("пришло");
        assert_eq!(&payload[..], b"answer");
        assert_eq!(from, source);
        reader.abort();
    }

    #[tokio::test]
    async fn two_replies_in_one_chunk_are_read_one_by_one() {
        let (client, mut server) = tokio::io::duplex(4096);
        let (sender, mut incoming) = mpsc::channel(8);
        let source = SocketAddress::domain("dns.example.com", 53);

        let boxed: Box<dyn ProxyStream> = Box::new(client);
        let (recv, _send) = tokio::io::split(boxed);
        let reader = tokio::spawn(read_replies(recv, source, sender));

        let mut wire = udp::encode(b"one").expect("собирается");
        wire.extend_from_slice(&udp::encode(b"two").expect("собирается"));
        server.write_all(&wire).await.expect("ушло");

        assert_eq!(&incoming.recv().await.expect("пришло").0[..], b"one");
        assert_eq!(&incoming.recv().await.expect("пришло").0[..], b"two");
        reader.abort();
    }

    #[tokio::test]
    async fn a_closed_stream_ends_the_reader_without_an_error() {
        let (client, server) = tokio::io::duplex(4096);
        let (sender, mut incoming) = mpsc::channel(8);

        let boxed: Box<dyn ProxyStream> = Box::new(client);
        let (recv, _send) = tokio::io::split(boxed);
        let reader = tokio::spawn(read_replies(
            recv,
            SocketAddress::domain("dns.example.com", 53),
            sender,
        ));
        drop(server);

        reader.await.expect("задача кончилась сама");
        assert!(incoming.recv().await.is_none());
    }
}
