//! Направление уровня пакетов, надетое на трейт [`Outbound`].
//!
//! ```text
//!   конвейер ──► Outbound ──► PacketTunnel ──► netstack::outgoing
//!                                                    │
//!                                             PacketDevice
//!                                                    │
//!                                             PacketOutbound (WireGuard)
//! ```
//!
//! Имена разрешаются внутри тоннеля ([`crate::packet_dns`]) серверами из
//! [`PacketInterface::dns`]; пустой список — домен честно отвергается, а не
//! разрешается мимо тоннеля.
//!
//! [`PacketInterface::dns`]: penguin_proto::packet::PacketInterface::dns

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use penguin_core::address::{Address, SocketAddress};
use penguin_core::id::OutboundId;
use penguin_netstack::Datagram;
use penguin_netstack::config::StackConfig;
use penguin_netstack::outgoing::{self, ConnectError, Connector};
use penguin_proto::capabilities::Capabilities;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::packet::PacketOutbound;
use penguin_proto::stream::ProxyStream;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use crate::packet::PacketDevice;
use crate::packet_dns::TunnelResolver;

/// Сколько датаграмм держать в очереди одной сессии.
const SESSION_QUEUE: usize = 128;

type Answer = (Bytes, SocketAddr);

/// Кому какая сессия принадлежит (замок не держится через `.await`).
type Sessions = Arc<RwLock<HashMap<SocketAddr, mpsc::Sender<Answer>>>>;

/// Пакетное направление, выглядящее для движка обычным.
pub struct PacketTunnel {
    inner: Arc<Inner>,
}

/// Общее для направления и его каналов: каналу датаграмм тоже нужно
/// разрешать имена, открывая отдельный канал.
struct Inner {
    outbound: Arc<dyn PacketOutbound>,
    connector: Connector,
    udp_send: mpsc::Sender<Datagram>,
    sessions: Sessions,
    next_tag: AtomicU16,
    resolver: TunnelResolver,
    cancel: CancellationToken,
}

impl PacketTunnel {
    /// Поднимает исходящий стек; отмена своя — закрытие профиля гасит только его.
    pub fn new(outbound: Arc<dyn PacketOutbound>) -> Self {
        let device = PacketDevice::new(Arc::clone(&outbound));
        let config = device.stack_config();
        let servers = outbound.interface().dns;
        let cancel = CancellationToken::new();
        let handles = outgoing::spawn(Box::new(device), config, cancel.clone());

        let sessions: Sessions = Sessions::default();
        tokio::spawn(demultiplex(
            handles.udp_recv,
            Arc::clone(&sessions),
            cancel.clone(),
        ));

        Self {
            inner: Arc::new(Inner {
                outbound,
                connector: handles.connector,
                udp_send: handles.udp_send,
                sessions,
                next_tag: AtomicU16::new(1),
                resolver: TunnelResolver::new(servers),
                cancel,
            }),
        }
    }

    /// Настройки стека — для журнала и тестов.
    pub fn stack_config(&self) -> StackConfig {
        PacketDevice::new(Arc::clone(&self.inner.outbound)).stack_config()
    }
}

impl Inner {
    /// Свободная метка сессии: выдуманный адрес, на провод не попадает.
    fn take_tag(&self) -> Option<SocketAddr> {
        let sessions = self.sessions.read();
        (0..u16::MAX).find_map(|_| {
            let port = self.next_tag.fetch_add(1, Ordering::Relaxed);
            let tag = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
            (port != 0 && !sessions.contains_key(&tag)).then_some(tag)
        })
    }

    /// Заводит канал датаграмм со своей меткой.
    fn open_channel(self: &Arc<Self>) -> Result<TunnelDatagram, ProtocolError> {
        let tag = self.take_tag().ok_or_else(|| {
            ProtocolError::Unreachable("свободных сессий UDP в тоннеле не осталось".to_owned())
        })?;
        let (incoming, answers) = mpsc::channel(SESSION_QUEUE);
        self.sessions.write().insert(tag, incoming);

        Ok(TunnelDatagram {
            tag,
            answers: Mutex::new(answers),
            inner: Arc::clone(self),
        })
    }

    /// Адрес назначения; имя спрашивается внутри тоннеля по отдельному каналу.
    async fn address_of(
        self: &Arc<Self>,
        target: &SocketAddress,
    ) -> Result<SocketAddr, ProtocolError> {
        match &target.host {
            Address::Ip(ip) => Ok(SocketAddr::new(*ip, target.port)),
            Address::Domain(name) => {
                if let Some(address) = self.resolver.cached(name) {
                    return Ok(SocketAddr::new(address, target.port));
                }
                let channel = self.open_channel()?;
                let address = self
                    .resolver
                    .resolve(name, &channel, penguin_dns::message::random_id())
                    .await?;
                Ok(SocketAddr::new(address, target.port))
            }
        }
    }
}

impl std::fmt::Debug for PacketTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketTunnel")
            .field("protocol", &self.inner.outbound.protocol())
            .finish()
    }
}

#[async_trait]
impl Outbound for PacketTunnel {
    fn id(&self) -> OutboundId {
        self.inner.outbound.id()
    }

    fn protocol(&self) -> &'static str {
        self.inner.outbound.protocol()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            udp: true,
            // Имя разрешаем сами, запросом внутрь тоннеля.
            remote_dns: false,
            multiplex: true,
            ..Capabilities::default()
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let address = self.inner.address_of(target).await?;
        let stream = self
            .inner
            .connector
            .connect(address)
            .await
            .map_err(translate)?;
        Ok(Box::new(stream))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        Ok(Box::new(self.inner.open_channel()?))
    }

    fn is_alive(&self) -> bool {
        self.inner.outbound.is_alive()
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.inner.cancel.cancel();
        self.inner.outbound.close().await
    }
}

/// Разводит ответы единой очереди стека по сессиям (по метке).
async fn demultiplex(
    mut answers: mpsc::Receiver<Datagram>,
    sessions: Sessions,
    cancel: CancellationToken,
) {
    loop {
        let datagram = tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            datagram = answers.recv() => datagram,
        };
        let Some(datagram) = datagram else { break };

        // `try_send`: медленная сессия не тормозит остальные.
        let sent = sessions
            .read()
            .get(&datagram.source)
            .map(|session| session.try_send((datagram.payload, datagram.destination)));
        if matches!(sent, Some(Err(_))) {
            tracing::trace!("очередь сессии UDP переполнена, ответ отброшен");
        }
    }
}

/// Датаграммный канал одной сессии приложения.
struct TunnelDatagram {
    tag: SocketAddr,
    answers: Mutex<mpsc::Receiver<Answer>>,
    inner: Arc<Inner>,
}

impl std::fmt::Debug for TunnelDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelDatagram")
            .field("tag", &self.tag)
            .finish()
    }
}

#[async_trait]
impl ProxyDatagram for TunnelDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let destination = self.inner.address_of(target).await?;
        self.inner
            .udp_send
            .send(Datagram {
                source: self.tag,
                destination,
                payload,
            })
            .await
            .map_err(|_| ProtocolError::Disconnected("тоннель остановлен".to_owned()))
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let (payload, from) = self
            .answers
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| ProtocolError::Disconnected("тоннель остановлен".to_owned()))?;
        Ok((
            payload,
            SocketAddress::new(Address::Ip(from.ip()), from.port()),
        ))
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.inner.sessions.write().remove(&self.tag);
        Ok(())
    }
}

impl Drop for TunnelDatagram {
    /// Конвейер роняет канал по таймауту тишины, не закрывая.
    fn drop(&mut self) {
        self.inner.sessions.write().remove(&self.tag);
    }
}

/// Отказ стека на языке протокола: по варианту `supervisor` решает о повторе.
fn translate(error: ConnectError) -> ProtocolError {
    match error {
        ConnectError::Refused(address) => {
            ProtocolError::Unreachable(format!("{address} отказал в соединении"))
        }
        ConnectError::TimedOut(address) => {
            ProtocolError::Connect(format!("нет ответа от {address}"))
        }
        ConnectError::NoAddress(address) => ProtocolError::InvalidConfig(format!(
            "у интерфейса тоннеля нет адреса, с которого идти на {address}"
        )),
        ConnectError::NoPorts => {
            ProtocolError::Unreachable("свободных портов в тоннеле не осталось".to_owned())
        }
        ConnectError::Stopped => ProtocolError::Disconnected("тоннель остановлен".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    use bytes::Bytes;
    use penguin_proto::packet::PacketInterface;

    use super::*;

    /// Направление, которое никуда не ходит.
    struct Silent {
        sent: Mutex<Vec<Vec<u8>>>,
        dns: Vec<std::net::IpAddr>,
    }

    impl Silent {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                sent: Mutex::new(Vec::new()),
                dns: Vec::new(),
            })
        }

        fn with_dns() -> Arc<Self> {
            Arc::new(Self {
                sent: Mutex::new(Vec::new()),
                dns: vec!["10.7.0.53".parse().expect("адрес")],
            })
        }
    }

    #[async_trait]
    impl PacketOutbound for Silent {
        fn id(&self) -> OutboundId {
            OutboundId::new("проверка")
        }

        fn protocol(&self) -> &'static str {
            "wireguard"
        }

        fn interface(&self) -> PacketInterface {
            PacketInterface {
                ipv4: (Ipv4Addr::new(10, 7, 0, 2), 24),
                ipv6: None,
                mtu: 1420,
                dns: self.dns.clone(),
            }
        }

        async fn send(&self, packet: &[u8]) -> Result<(), ProtocolError> {
            self.sent.lock().expect("замок").push(packet.to_vec());
            Ok(())
        }

        async fn recv(&self) -> Result<Bytes, ProtocolError> {
            // Сервер, до которого не дошло.
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn the_tunnel_looks_like_an_ordinary_direction() {
        let tunnel = PacketTunnel::new(Silent::new());
        assert_eq!(tunnel.protocol(), "wireguard");
        assert_eq!(tunnel.id(), OutboundId::new("проверка"));

        let capabilities = tunnel.capabilities();
        assert!(capabilities.multiplex, "соединения живут в одном тоннеле");
        assert!(
            !capabilities.remote_dns,
            "имя разрешает не та сторона, а мы сами"
        );
    }

    #[tokio::test]
    async fn the_stack_gets_the_address_the_server_gave() {
        let tunnel = PacketTunnel::new(Silent::new());
        let config = tunnel.stack_config();
        assert_eq!(config.ipv4, (Ipv4Addr::new(10, 7, 0, 2), 24));
        assert_eq!(config.mtu, 1420);
    }

    #[tokio::test]
    async fn a_domain_is_refused_with_an_explanation_not_resolved_outside() {
        let tunnel = PacketTunnel::new(Silent::new());
        let target: SocketAddress = "example.com:443".parse().expect("адрес");

        // У `dyn ProxyStream` нет `Debug`, `unwrap_err` не годится.
        let error = tunnel
            .connect_tcp(&target)
            .await
            .err()
            .expect("имя не должно разрешаться мимо тоннеля");
        assert!(!error.is_retryable(), "повтор ничего не изменит");
        assert!(error.to_string().contains("example.com"), "{error}");
    }

    #[tokio::test]
    async fn the_name_servers_the_interface_gave_reach_the_resolver() {
        let with = PacketTunnel::new(Silent::with_dns());
        assert!(!with.inner.resolver.is_empty());

        let without = PacketTunnel::new(Silent::new());
        assert!(without.inner.resolver.is_empty());
    }

    #[tokio::test]
    async fn a_name_query_goes_into_the_tunnel_and_not_around_it() {
        // Ответа не будет; важен сам факт запроса в направление.
        let outbound = Silent::with_dns();
        let tunnel = PacketTunnel::new(Arc::clone(&outbound) as Arc<dyn PacketOutbound>);
        let target: SocketAddress = "example.com:443".parse().expect("адрес");

        let attempt = tokio::spawn(async move { tunnel.connect_tcp(&target).await.is_ok() });
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        assert!(
            !outbound.sent.lock().expect("замок").is_empty(),
            "запрос имени не ушёл в тоннель"
        );
        attempt.abort();
    }

    #[tokio::test]
    async fn every_udp_session_gets_its_own_tag() {
        let tunnel = PacketTunnel::new(Silent::new());
        let first = tunnel.bind_udp().await.expect("канал");
        let second = tunnel.bind_udp().await.expect("канал");

        assert_eq!(tunnel.inner.sessions.read().len(), 2);
        drop(first);
        drop(second);
    }

    #[tokio::test]
    async fn a_closed_session_frees_its_tag() {
        let tunnel = PacketTunnel::new(Silent::new());
        let channel = tunnel.bind_udp().await.expect("канал");
        assert_eq!(tunnel.inner.sessions.read().len(), 1);

        channel.close().await.expect("закрылся");
        assert!(tunnel.inner.sessions.read().is_empty());
    }

    #[tokio::test]
    async fn a_dropped_session_frees_its_tag_too() {
        let tunnel = PacketTunnel::new(Silent::new());
        drop(tunnel.bind_udp().await.expect("канал"));
        assert!(tunnel.inner.sessions.read().is_empty());
    }

    #[tokio::test]
    async fn a_datagram_reaches_the_direction_as_a_packet() {
        let outbound = Silent::new();
        let tunnel = PacketTunnel::new(Arc::clone(&outbound) as Arc<dyn PacketOutbound>);
        let channel = tunnel.bind_udp().await.expect("канал");

        let target: SocketAddress = "8.8.8.8:53".parse().expect("адрес");
        channel
            .send_to(Bytes::from_static(b"query"), &target)
            .await
            .expect("ушла");

        // Стеку нужен оборот цикла, чтобы собрать пакет.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let sent = outbound.sent.lock().expect("замок");
        assert!(
            sent.iter().any(|packet| packet.ends_with(b"query")),
            "датаграмма не дошла до направления"
        );
    }

    #[tokio::test]
    async fn a_domain_is_refused_on_the_datagram_side_as_well() {
        let tunnel = PacketTunnel::new(Silent::new());
        let channel = tunnel.bind_udp().await.expect("канал");
        let target: SocketAddress = "dns.example.com:53".parse().expect("адрес");

        let error = channel
            .send_to(Bytes::from_static(b"query"), &target)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("dns.example.com"), "{error}");
    }

    #[tokio::test]
    async fn packets_reach_the_direction_when_a_connection_is_attempted() {
        let outbound = Silent::new();
        let tunnel = PacketTunnel::new(Arc::clone(&outbound) as Arc<dyn PacketOutbound>);
        let target: SocketAddress = "93.184.216.34:443".parse().expect("адрес");

        // Ответа не будет — ждём только первого пакета.
        let attempt = tokio::spawn(async move { tunnel.connect_tcp(&target).await });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        assert!(
            !outbound.sent.lock().expect("замок").is_empty(),
            "в тоннель не ушло ни одного пакета: стек не поднят"
        );
        attempt.abort();
    }

    #[test]
    fn silence_is_retried_and_a_wrong_interface_is_not() {
        let address = "93.184.216.34:443".parse().expect("адрес");

        assert!(translate(ConnectError::TimedOut(address)).is_retryable());
        assert!(translate(ConnectError::Refused(address)).is_retryable());
        assert!(!translate(ConnectError::NoAddress(address)).is_retryable());
    }
}
