//! Прямой выход в обход тоннеля: сокет, привязанный к физическому интерфейсу.
//!
//! Нужен правилу `direct` и самим протоколам ([`penguin_proto::dialer::Dialer`]):
//! пока TUN — маршрут по умолчанию, их сокеты иначе уехали бы в тоннель.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use penguin_core::address::{Address, SocketAddress};
use penguin_core::id::OutboundId;
use penguin_dns::resolver::Resolver;
use penguin_proto::capabilities::Capabilities;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// Наибольшая датаграмма UDP: меньший буфер портил бы данные молча.
const MAX_DATAGRAM: usize = 65_535;

/// Системное число сокета (дескриптор на unix, `SOCKET` на Windows).
trait SocketHandle {
    #[cfg(unix)]
    fn handle(&self) -> std::os::fd::RawFd;
    #[cfg(windows)]
    fn handle(&self) -> std::os::windows::io::RawSocket;
}

#[cfg(unix)]
impl<T: std::os::fd::AsRawFd> SocketHandle for T {
    fn handle(&self) -> std::os::fd::RawFd {
        self.as_raw_fd()
    }
}

#[cfg(windows)]
impl<T: std::os::windows::io::AsRawSocket> SocketHandle for T {
    fn handle(&self) -> std::os::windows::io::RawSocket {
        self.as_raw_socket()
    }
}

/// Выход наружу мимо тоннеля.
pub struct SystemDialer {
    /// Адрес физического интерфейса; `None` — привязка не нужна.
    bind_to: Option<IpAddr>,
    /// Номер физического интерфейса; ноль — тоннеля нет. Адреса мало: маршрут
    /// выбирает таблица, привязка к интерфейсу её обходит
    /// ([`penguin_platform::bind`]). Общий с сокетами загрузочного разрешателя.
    interface: Arc<AtomicU32>,
    /// Разрешатель имён мимо тоннеля.
    resolver: Arc<dyn Resolver>,
}

impl std::fmt::Debug for SystemDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemDialer")
            .field("bind_to", &self.bind_to)
            .field("interface", &self.interface.load(Ordering::Relaxed))
            .finish()
    }
}

impl SystemDialer {
    /// Выход без привязки к интерфейсу.
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self {
            bind_to: None,
            interface: Arc::new(AtomicU32::new(0)),
            resolver,
        }
    }

    /// Выход с загрузочным разрешателем ([`penguin_dns::bootstrap`]): системный подменён
    /// и отвечает fake-IP. Сокеты разрешателя защищены вместе со всеми: иначе при поднятом
    /// тоннеле запрос ушёл бы в него же, к перехвату DNS, который ждёт этого ответа.
    pub fn bootstrapped(dns: &penguin_dns::config::DnsConfig) -> Self {
        // Разрешатель у этих сокетов не спрашивают: адреса апстримов числовые.
        let sockets = Arc::new(Self::new(Arc::new(penguin_dns::resolver::SystemResolver)));
        let resolver =
            penguin_dns::bootstrap::resolver_for(dns, Arc::clone(&sockets) as Arc<dyn Dialer>);
        Self {
            bind_to: None,
            interface: Arc::clone(&sockets.interface),
            resolver,
        }
    }

    /// Привязывает исходящие сокеты к указанному адресу.
    pub fn bound_to(mut self, address: IpAddr) -> Self {
        self.bind_to = Some(address);
        self
    }

    /// Защищает сокеты интерфейсом на время тоннеля; ноль снимает защиту.
    pub fn protect_with(&self, interface: u32) {
        self.interface.store(interface, Ordering::Relaxed);
    }

    /// Привязывает сокет к физическому интерфейсу; отказ набор не прерывает.
    fn protect(&self, socket: &impl SocketHandle, ipv6: bool) {
        let interface = self.interface.load(Ordering::Relaxed);
        if interface == 0 {
            return;
        }
        if let Err(err) = penguin_platform::bind::to_interface(socket.handle(), interface, ipv6) {
            tracing::warn!(%err, interface, "сокет не защищён от тоннеля");
        }
    }

    /// Локальный адрес для привязки; другое семейство — без привязки.
    fn local_for(&self, remote: SocketAddr) -> Option<SocketAddr> {
        let bind = self.bind_to?;
        (bind.is_ipv4() == remote.is_ipv4()).then(|| SocketAddr::new(bind, 0))
    }
}

#[async_trait]
impl Dialer for SystemDialer {
    async fn dial_tcp(&self, addr: SocketAddr) -> Result<TcpStream, ProtocolError> {
        let socket = match addr {
            SocketAddr::V4(_) => TcpSocket::new_v4(),
            SocketAddr::V6(_) => TcpSocket::new_v6(),
        }?;

        if let Some(local) = self.local_for(addr) {
            socket.bind(local)?;
        }
        // До `connect`: маршрут выбирается в нём.
        self.protect(&socket, addr.is_ipv6());

        let stream = socket.connect(addr).await?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }

    async fn bind_udp(&self, local: SocketAddr) -> Result<UdpSocket, ProtocolError> {
        let local = self.local_for(local).unwrap_or(local);
        let socket = UdpSocket::bind(local).await?;
        self.protect(&socket, local.is_ipv6());
        Ok(socket)
    }

    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ProtocolError> {
        let addresses =
            self.resolver.resolve(host).await.map_err(|e| {
                ProtocolError::Connect(format!("не удалось разрешить `{host}`: {e}"))
            })?;

        if addresses.is_empty() {
            return Err(ProtocolError::Connect(format!(
                "имя `{host}` никуда не разрешается"
            )));
        }
        Ok(addresses)
    }
}

/// Числовой адрес назначения; имя разрешается набирателем.
async fn socket_addr(
    dialer: &dyn Dialer,
    target: &SocketAddress,
) -> Result<SocketAddr, ProtocolError> {
    match &target.host {
        Address::Ip(ip) => Ok(SocketAddr::new(*ip, target.port)),
        Address::Domain(domain) => dialer
            .resolve(domain)
            .await?
            .into_iter()
            .next()
            .map(|ip| SocketAddr::new(ip, target.port))
            .ok_or_else(|| ProtocolError::Unreachable(domain.clone())),
    }
}

/// Прямой выход как обычное направление пула: ветки «напрямую» в движке нет.
pub struct DirectOutbound {
    dialer: Arc<dyn Dialer>,
}

impl std::fmt::Debug for DirectOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectOutbound").finish_non_exhaustive()
    }
}

impl DirectOutbound {
    /// Создаёт прямой выход поверх этого набирателя.
    pub fn new(dialer: Arc<dyn Dialer>) -> Self {
        Self { dialer }
    }
}

#[async_trait]
impl Outbound for DirectOutbound {
    fn id(&self) -> OutboundId {
        OutboundId::direct()
    }

    fn protocol(&self) -> &'static str {
        "direct"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            udp: true,
            multiplex: false,
            port_hopping: false,
            remote_dns: false,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let addr = socket_addr(&*self.dialer, target).await?;
        let stream = self.dialer.dial_tcp(addr).await.inspect_err(|err| {
            tracing::debug!(%target, %addr, %err, "прямое соединение не открылось");
        })?;
        tracing::debug!(%target, %addr, "прямое соединение открыто");
        Ok(Box::new(stream))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        // Только IPv4: двойной стек включается не везде одинаково.
        let local = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        let socket = self.dialer.bind_udp(local).await?;
        Ok(Box::new(DirectDatagram {
            socket,
            dialer: Arc::clone(&self.dialer),
            resolved: parking_lot::Mutex::new(None),
        }))
    }
}

/// Датаграммный канал прямого выхода.
struct DirectDatagram {
    socket: UdpSocket,
    dialer: Arc<dyn Dialer>,
    /// Последнее разрешённое имя: иначе каждая датаграмма QUIC уходила бы в DNS.
    resolved: parking_lot::Mutex<Option<(SocketAddress, SocketAddr)>>,
}

impl DirectDatagram {
    /// Адрес IPv4 назначения: сокет только IPv4, адрес IPv6 он отверг бы (`EINVAL`).
    async fn address_of(&self, target: &SocketAddress) -> Result<SocketAddr, ProtocolError> {
        let domain = match &target.host {
            Address::Ip(ip) => return Ok(SocketAddr::new(*ip, target.port)),
            Address::Domain(domain) => domain,
        };
        if let Some((name, addr)) = &*self.resolved.lock()
            && name == target
        {
            return Ok(*addr);
        }

        let addr = self
            .dialer
            .resolve(domain)
            .await?
            .into_iter()
            .find(IpAddr::is_ipv4)
            .map(|ip| SocketAddr::new(ip, target.port))
            .ok_or_else(|| ProtocolError::Unreachable(format!("у `{domain}` нет адреса IPv4")))?;
        tracing::debug!(%target, %addr, "имя прямой датаграммы разрешено");
        *self.resolved.lock() = Some((target.clone(), addr));
        Ok(addr)
    }
}

#[async_trait]
impl ProxyDatagram for DirectDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let addr = self.address_of(target).await?;
        self.socket.send_to(&payload, addr).await?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        // Без обнуления буфера; наружу уходит копия точного размера.
        let mut buf = BytesMut::with_capacity(MAX_DATAGRAM);
        let (_, from) = self.socket.recv_buf_from(&mut buf).await?;
        Ok((Bytes::copy_from_slice(&buf), SocketAddress::from(from)))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use penguin_dns::resolver::SystemResolver;

    use super::*;

    fn dialer() -> SystemDialer {
        SystemDialer::new(Arc::new(SystemResolver))
    }

    #[test]
    fn unbound_dialer_does_not_bind() {
        assert!(
            dialer()
                .local_for("1.2.3.4:443".parse().expect("адрес"))
                .is_none()
        );
    }

    #[test]
    fn binds_when_families_match() {
        let dialer = dialer().bound_to(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        let local = dialer
            .local_for("1.2.3.4:443".parse().expect("адрес"))
            .expect("привязка");
        assert_eq!(local.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(local.port(), 0, "порт выбирает система");
    }

    #[test]
    fn skips_binding_across_families() {
        let dialer = dialer().bound_to(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert!(
            dialer
                .local_for("[2001:db8::1]:443".parse().expect("адрес"))
                .is_none()
        );

        let dialer = dialer.bound_to(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert!(
            dialer
                .local_for("1.2.3.4:443".parse().expect("адрес"))
                .is_none()
        );
    }

    #[tokio::test]
    async fn resolves_through_the_injected_resolver() {
        let addresses = dialer().resolve("127.0.0.1").await.expect("разбирается");
        assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }

    #[tokio::test]
    async fn empty_resolution_is_an_error() {
        struct Empty;

        #[async_trait]
        impl Resolver for Empty {
            async fn resolve(&self, _host: &str) -> penguin_dns::error::DnsResult<Vec<IpAddr>> {
                Ok(Vec::new())
            }
        }

        let dialer = SystemDialer::new(Arc::new(Empty));
        assert!(dialer.resolve("nowhere.invalid").await.is_err());
    }

    #[tokio::test]
    async fn datagram_roundtrip_keeps_exact_size() {
        let direct = DirectOutbound::new(Arc::new(dialer()));
        let channel = direct.bind_udp().await.expect("сокет");
        let peer = UdpSocket::bind("127.0.0.1:0").await.expect("сокет");
        let peer_addr = peer.local_addr().expect("адрес");

        channel
            .send_to(Bytes::from_static(b"ping"), &SocketAddress::from(peer_addr))
            .await
            .expect("отправлено");
        let mut buf = [0u8; 16];
        let (len, from) = peer.recv_from(&mut buf).await.expect("получено");
        assert_eq!(&buf[..len], b"ping");

        peer.send_to(b"pong", from).await.expect("отправлено");
        let (payload, _) = channel.recv_from().await.expect("получено");
        assert_eq!(&payload[..], b"pong");
    }
}
