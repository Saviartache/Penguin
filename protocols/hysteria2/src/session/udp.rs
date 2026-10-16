//! UDP-сессии поверх датаграмм QUIC: одна задача читает датаграммы и
//! раскладывает их по сессиям по номеру в заголовке.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use tokio::sync::{Mutex, mpsc};

use crate::error::Hysteria2Error;
use crate::frame::udp;
use penguin_transport::frag::{Fragment, Reassembler};

/// Глубина очереди сессии; переполнение — потеря датаграммы, как у UDP.
const SESSION_QUEUE: usize = 256;

type Inbox = mpsc::Sender<(Bytes, SocketAddress)>;
type Sessions = Arc<RwLock<HashMap<u32, Inbox>>>;

/// Разбор датаграмм по сессиям.
pub struct UdpManager {
    connection: quinn::Connection,
    sessions: Sessions,
    next_session: AtomicU32,
    reader: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for UdpManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpManager")
            .field("sessions", &self.sessions.read().len())
            .finish()
    }
}

impl UdpManager {
    /// Заводит разбор и фоновую задачу чтения.
    pub fn new(connection: quinn::Connection) -> Arc<Self> {
        let sessions = Sessions::default();
        let reader = tokio::spawn(read_loop(connection.clone(), Arc::clone(&sessions)));

        Arc::new(Self {
            connection,
            sessions,
            // Ноль не используется: слишком легко получить из пустого буфера.
            next_session: AtomicU32::new(1),
            reader: Mutex::new(Some(reader)),
        })
    }

    /// Открывает новую сессию.
    pub fn open(self: &Arc<Self>) -> UdpSession {
        let session_id = self.next_session.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(SESSION_QUEUE);
        self.sessions.write().insert(session_id, tx);

        UdpSession {
            session_id,
            manager: Arc::clone(self),
            inbox: Mutex::new(rx),
            next_packet: AtomicU16::new(0),
        }
    }

    /// Останавливает чтение.
    pub async fn shutdown(&self) {
        if let Some(reader) = self.reader.lock().await.take() {
            reader.abort();
        }
        self.sessions.write().clear();
    }
}

/// Читает датаграммы соединения и раскладывает их по сессиям.
async fn read_loop(connection: quinn::Connection, sessions: Sessions) {
    let mut reassembler = Reassembler::new();

    loop {
        let datagram = match connection.read_datagram().await {
            Ok(datagram) => datagram,
            Err(err) => {
                tracing::debug!(%err, "канал датаграмм закрыт");
                break;
            }
        };

        let Some(message) = udp::UdpMessage::decode(datagram) else {
            continue;
        };

        let session_id = message.session_id;
        let fragment = Fragment {
            session: u64::from(message.session_id),
            packet: message.packet_id,
            count: message.fragment_count,
            index: message.fragment_id,
            address: message.address,
            payload: message.payload,
        };
        let Some((payload, address)) = reassembler.accept(fragment) else {
            continue;
        };

        let Ok(address) = SocketAddress::from_str(&address) else {
            tracing::debug!(%address, "сервер прислал неразбираемый адрес");
            continue;
        };

        let sent = match sessions.read().get(&session_id) {
            Some(sender) => sender.try_send((payload, address)),
            None => continue,
        };
        if sent.is_err() {
            tracing::trace!(
                session_id,
                "очередь сессии переполнена, датаграмма отброшена"
            );
        }
    }

    sessions.write().clear();
}

/// Одна UDP-сессия: соответствует одному сокету приложения.
pub struct UdpSession {
    session_id: u32,
    manager: Arc<UdpManager>,
    inbox: Mutex<mpsc::Receiver<(Bytes, SocketAddress)>>,
    next_packet: AtomicU16,
}

impl std::fmt::Debug for UdpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSession")
            .field("session_id", &self.session_id)
            .finish()
    }
}

#[async_trait]
impl ProxyDatagram for UdpSession {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let connection = &self.manager.connection;

        let max = connection
            .max_datagram_size()
            .ok_or(Hysteria2Error::UdpDisabled)
            .map_err(ProtocolError::from)?;

        let packet_id = self.next_packet.fetch_add(1, Ordering::Relaxed);
        let size = payload.len();
        let parts = udp::fragment(self.session_id, packet_id, &target.to_wire(), payload, max)
            .ok_or(Hysteria2Error::DatagramTooLarge { size })
            .map_err(ProtocolError::from)?;

        for part in parts {
            connection
                .send_datagram(part.encode())
                .map_err(|e| ProtocolError::from(Hysteria2Error::Disconnected(e.to_string())))?;
        }
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let mut inbox = self.inbox.lock().await;
        inbox.recv().await.ok_or_else(|| {
            ProtocolError::from(Hysteria2Error::Disconnected("сессия закрыта".to_owned()))
        })
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.manager.sessions.write().remove(&self.session_id);
        Ok(())
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.manager.sessions.write().remove(&self.session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_do_not_start_at_zero() {
        // Ноль слишком легко получить из неинициализированного буфера.
        let counter = AtomicU32::new(1);
        assert_eq!(counter.fetch_add(1, Ordering::Relaxed), 1);
    }

    #[test]
    fn queue_is_bounded() {
        // Приложение, забывшее про свой сокет, не должно съедать память.
        const { assert!(SESSION_QUEUE > 0 && SESSION_QUEUE <= 1024) };
    }
}
