//! Канал датаграмм: по потоку на адресата — тот же приём, что и у VLESS.
//!
//! Адрес назначения назван **один раз**, в заголовке запроса: значит, поток
//! обслуживает одного адресата, а канал датаграмм приложения — сколько
//! угодно адресатов сразу. Держать их все, разбирать, кто ответил, и
//! закрывать по времени жизни канала приходится самому клиенту — устройство
//! и код здесь дословно повторяют `penguin_vless::datagram`, отличаясь
//! только тем, что несёт сам поток: там — кадр VLESS без шифрования, здесь —
//! кадр тела VMess ([`crate::frame::body`]), уже встроенный в
//! [`crate::stream::VmessStream`], так что читать и писать можно как обычный
//! байтовый поток.
//!
//! `security = "zero"` с UDP несовместим и отклоняется в
//! [`crate::config::VmessConfig::validate`] — у `zero` нет ни единой границы
//! куска, а с ней невозможно понять, где кончается одна датаграмма и
//! начинается следующая.

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
use crate::error::VmessError;
use crate::frame::request::CMD_UDP;

/// Сколько адресатов канал держит одновременно.
pub const MAX_SESSIONS: usize = 256;

/// Сколько ответов держать в очереди, пока их не забрали.
const QUEUE: usize = 512;

/// Сколько байт брать из потока за раз.
const CHUNK: usize = 16 * 1024;

/// Канал датаграмм через сервер VMess.
pub struct VmessDatagram {
    connector: Arc<Connector>,
    sessions: Mutex<HashMap<SocketAddress, Session>>,
    incoming: Mutex<mpsc::Receiver<(Bytes, SocketAddress)>>,
    sender: mpsc::Sender<(Bytes, SocketAddress)>,
}

/// Один адресат: куда писать и кто читает.
struct Session {
    send: WriteHalf<Box<dyn ProxyStream>>,
    reader: JoinHandle<()>,
}

impl std::fmt::Debug for VmessDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessDatagram")
            .field("connector", &self.connector)
            .finish()
    }
}

impl VmessDatagram {
    /// Собирает канал. Потоков при этом не открывается: их заводит первая
    /// посылка каждому адресату.
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
impl ProxyDatagram for VmessDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let mut sessions = self.sessions.lock().await;

        if !sessions.contains_key(target) {
            if sessions.len() >= MAX_SESSIONS {
                return Err(ProtocolError::Unsupported(
                    "больше адресатов в одном канале VMess не помещается",
                ));
            }

            let io = self.connector.open(CMD_UDP, target).await?;
            let (recv, send) = tokio::io::split(io);
            let reader = tokio::spawn(read_replies(recv, target.clone(), self.sender.clone()));
            sessions.insert(target.clone(), Session { send, reader });
        }

        let Some(session) = sessions.get_mut(target) else {
            return Err(VmessError::Disconnected("поток до адресата пропал".into()).into());
        };

        // Обрыв одного адресата — это не конец канала: остальные живут.
        if let Err(err) = write_payload(&mut session.send, &payload).await {
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
            .ok_or_else(|| VmessError::Disconnected("канал датаграмм закрыт".to_owned()).into())
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

impl Drop for VmessDatagram {
    fn drop(&mut self) {
        if let Ok(sessions) = self.sessions.try_lock() {
            for session in sessions.values() {
                session.reader.abort();
            }
        }
    }
}

/// Пишет одну датаграмму в поток адресата.
///
/// Границы куска даёт сам [`crate::stream::VmessStream`] — здесь ровно один
/// `write_all` на одну датаграмму, без своей длины поверх: второй такой
/// поверх кадра тела означал бы двойную рамку там, где хватает одной.
async fn write_payload(
    send: &mut WriteHalf<Box<dyn ProxyStream>>,
    payload: &[u8],
) -> Result<(), VmessError> {
    send.write_all(payload).await?;
    send.flush().await?;
    Ok(())
}

/// Читает ответы одного адресата и складывает их в общую очередь.
async fn read_replies(
    mut io: ReadHalf<Box<dyn ProxyStream>>,
    source: SocketAddress,
    sender: mpsc::Sender<(Bytes, SocketAddress)>,
) {
    let mut buffer = BytesMut::with_capacity(CHUNK);
    buffer.resize(CHUNK, 0);

    loop {
        let read = match io.read(&mut buffer).await {
            Ok(0) => {
                tracing::debug!(%source, "поток датаграмм закрыт сервером");
                return;
            }
            Ok(read) => read,
            Err(err) => {
                tracing::debug!(%source, %err, "поток датаграмм оборвался");
                return;
            }
        };

        let payload = Bytes::copy_from_slice(&buffer[..read]);
        if sender.send((payload, source.clone())).await.is_err() {
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

        server.write_all(b"answer").await.expect("ушло");

        let (payload, from) = incoming.recv().await.expect("пришло");
        assert_eq!(&payload[..], b"answer");
        assert_eq!(from, source);
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
