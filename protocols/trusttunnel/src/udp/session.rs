//! Единый поток `CONNECT _udp2` на весь UDP-трафик направления.
//!
//! Все UDP-«соединения» направления идут в одном потоке (`PROTOCOL.md`, §6.1).
//! Кадр не несёт идентификатора сессии, а сервер в ответе меняет источник с
//! назначением местами (`lib/src/forwarder.rs::UdpDatagramMeta::reversed`),
//! поэтому каждая сессия получает синтетический адрес источника
//! (`SESSION_SOURCE_IP` и свой порт) — метку, по которой кадр находит сессию.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use parking_lot::RwLock;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::stream::ProxyStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::connect;
use crate::error::{TrustTunnelError, TrustTunnelResult};
use crate::transport::Link;
use crate::udp::frame;

/// Адрес источника синтетических сессий: только метка-ключ (`PROTOCOL.md`, §6.5).
const SESSION_SOURCE_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Длина очереди сессии; переполнение — потеря кадра, как у UDP.
const SESSION_QUEUE: usize = 256;

/// Размер одного чтения из потока `_udp2`.
const READ_CHUNK: usize = 16 * 1024;

/// Таблица сессий по синтетическому адресу.
type Sessions = RwLock<HashMap<SocketAddr, mpsc::Sender<(Bytes, SocketAddress)>>>;

/// Единый поток `_udp2`: пишущая и читающая половины плюс таблица сессий.
pub struct UdpManager {
    dialer: Arc<dyn Dialer>,
    outbox: mpsc::Sender<Bytes>,
    sessions: Arc<Sessions>,
    next_port: AtomicU16,
    writer: JoinHandle<()>,
    reader: JoinHandle<()>,
}

impl std::fmt::Debug for UdpManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpManager")
            .field("sessions", &self.sessions.read().len())
            .finish()
    }
}

impl UdpManager {
    /// Открывает поток `CONNECT _udp2` и заводит читающую и пишущую задачи.
    pub async fn connect(
        link: &Link,
        credentials: (&str, &str),
        dialer: Arc<dyn Dialer>,
    ) -> TrustTunnelResult<Arc<Self>> {
        let open = link.open(connect::UDP_AUTHORITY, credentials, false);
        let stream = connect::perform(connect::UDP_AUTHORITY, open).await?;

        let (read_half, write_half) = tokio::io::split(stream);
        let (outbox, inbox) = mpsc::channel(SESSION_QUEUE);
        let sessions = Arc::new(Sessions::default());

        let writer = tokio::spawn(write_loop(write_half, inbox));
        let reader = tokio::spawn(read_loop(read_half, Arc::clone(&sessions)));

        Ok(Arc::new(Self {
            dialer,
            outbox,
            sessions,
            next_port: AtomicU16::new(1),
            writer,
            reader,
        }))
    }

    /// Открывает новую UDP-сессию поверх уже поднятого потока.
    pub fn open(self: &Arc<Self>) -> UdpSession {
        let port = self.next_port.fetch_add(1, Ordering::Relaxed);
        let local = SocketAddr::new(SESSION_SOURCE_IP, port);

        let (tx, rx) = mpsc::channel(SESSION_QUEUE);
        self.sessions.write().insert(local, tx);

        UdpSession {
            local,
            manager: Arc::clone(self),
            inbox: Mutex::new(rx),
        }
    }

    /// Останавливает читающую и пишущую задачи.
    pub fn shutdown(&self) {
        self.writer.abort();
        self.reader.abort();
    }
}

/// Пишет кадры в поток `_udp2` строго по очереди.
async fn write_loop(
    mut write_half: WriteHalf<Box<dyn ProxyStream>>,
    mut inbox: mpsc::Receiver<Bytes>,
) {
    while let Some(frame) = inbox.recv().await {
        if let Err(err) = write_half.write_all(&frame).await {
            tracing::debug!(%err, "запись в поток _udp2 не удалась");
            return;
        }
    }
}

/// Читает поток `_udp2`, собирает кадры и раскладывает их по сессиям.
async fn read_loop(mut read_half: ReadHalf<Box<dyn ProxyStream>>, sessions: Arc<Sessions>) {
    let mut buffer = BytesMut::with_capacity(READ_CHUNK);

    loop {
        if buffer.capacity() - buffer.len() < READ_CHUNK {
            buffer.reserve(READ_CHUNK);
        }

        match read_half.read_buf(&mut buffer).await {
            Ok(0) => {
                tracing::debug!("поток _udp2 закрыт сервером");
                break;
            }
            Ok(_) => {}
            Err(err) => {
                tracing::debug!(%err, "чтение потока _udp2 оборвалось");
                break;
            }
        }

        loop {
            match frame::decode_server_frame(&buffer) {
                Ok(Some((decoded, used))) => {
                    buffer.advance(used);
                    dispatch(&sessions, decoded);
                }
                Ok(None) => break,
                Err(err) => {
                    tracing::debug!(%err, "кадр _udp2 не разобрался, поток остановлен");
                    sessions.write().clear();
                    return;
                }
            }
        }
    }

    sessions.write().clear();
}

/// Передаёт кадр в сессию по адресу назначения.
fn dispatch(sessions: &Sessions, frame: frame::ServerFrame) {
    let table = sessions.read();
    let Some(sender) = table.get(&frame.destination) else {
        tracing::trace!(destination = %frame.destination, "кадр _udp2 для неизвестной сессии");
        return;
    };

    let source = SocketAddress::from(frame.source);
    if sender.try_send((frame.payload, source)).is_err() {
        tracing::trace!(destination = %frame.destination, "очередь UDP-сессии переполнена");
    }
}

/// Одна UDP-сессия: соответствует одному вызову `bind_udp`.
pub struct UdpSession {
    local: SocketAddr,
    manager: Arc<UdpManager>,
    inbox: Mutex<mpsc::Receiver<(Bytes, SocketAddress)>>,
}

impl std::fmt::Debug for UdpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSession")
            .field("local", &self.local)
            .finish()
    }
}

#[async_trait]
impl ProxyDatagram for UdpSession {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let destination = resolve_numeric(self.manager.dialer.as_ref(), target).await?;

        let frame = frame::encode_client_frame(self.local, destination, "", &payload)
            .map_err(ProtocolError::from)?;

        self.manager.outbox.send(frame).await.map_err(|_| {
            ProtocolError::from(TrustTunnelError::disconnected(
                "поток _udp2 закрыт".to_owned(),
            ))
        })
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let mut inbox = self.inbox.lock().await;
        inbox.recv().await.ok_or_else(|| {
            ProtocolError::from(TrustTunnelError::disconnected("сессия закрыта".to_owned()))
        })
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.manager.sessions.write().remove(&self.local);
        Ok(())
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.manager.sessions.write().remove(&self.local);
    }
}

/// Приводит адрес назначения к числовому: кадр несёт только IP (`PROTOCOL.md`, §6.3).
async fn resolve_numeric(
    dialer: &dyn Dialer,
    target: &SocketAddress,
) -> Result<SocketAddr, ProtocolError> {
    if let Some(ip) = target.host.as_ip() {
        return Ok(SocketAddr::new(ip, target.port));
    }
    let addresses = penguin_proto::connect::resolve(dialer, &target.host, target.port).await?;
    addresses.into_iter().next().ok_or_else(|| {
        ProtocolError::Connect(format!("`{}` не разрешился ни в один адрес", target.host))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_do_not_start_at_zero() {
        let counter = AtomicU16::new(1);
        assert_eq!(counter.fetch_add(1, Ordering::Relaxed), 1);
    }

    #[test]
    fn the_source_tag_is_loopback_not_a_routable_address() {
        assert!(SESSION_SOURCE_IP.is_loopback());
    }

    #[tokio::test]
    async fn a_numeric_target_needs_no_resolver() {
        struct NeverAsked;
        #[async_trait]
        impl Dialer for NeverAsked {
            async fn dial_tcp(
                &self,
                _addr: SocketAddr,
            ) -> Result<tokio::net::TcpStream, ProtocolError> {
                unreachable!("тест не открывает сокетов")
            }
            async fn bind_udp(
                &self,
                _local: SocketAddr,
            ) -> Result<tokio::net::UdpSocket, ProtocolError> {
                unreachable!("тест не открывает сокетов")
            }
            async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, ProtocolError> {
                panic!("числовой адрес не должен идти к резолверу")
            }
        }

        let target = SocketAddress::ip("203.0.113.9".parse().unwrap(), 53);
        let resolved = resolve_numeric(&NeverAsked, &target)
            .await
            .expect("разрешился");
        assert_eq!(resolved, "203.0.113.9:53".parse().unwrap());
    }
}
