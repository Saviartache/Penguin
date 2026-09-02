//! Прямой выход в обход тоннеля: сокет, привязанный к физическому интерфейсу.
//!
//! Два потребителя, и оба важны.
//!
//! **Правило `direct`.** Приложение, которому пользователь велел ходить мимо
//! тоннеля, получает соединение отсюда.
//!
//! **Сам протокол.** Клиент Hysteria 2 открывает сокет к своему серверу через
//! этот же выход — иначе его пакеты попали бы в тоннель, который он и должен
//! поднять, и подключение не состоялось бы никогда. Это и есть реализация
//! [`penguin_proto::dialer::Dialer`].
//!
//! Привязка к интерфейсу нужна не всегда. Пока TUN не поднят — в режиме
//! прокси и до подключения — обычный сокет и так уходит наружу правильно.
//! Как только TUN становится маршрутом по умолчанию, сокет надо привязывать
//! к адресу физического интерфейса, иначе он уедет в тоннель.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_core::id::OutboundId;
use penguin_dns::resolver::Resolver;
use penguin_proto::capabilities::Capabilities;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// Выход наружу мимо тоннеля.
pub struct SystemDialer {
    /// Адрес физического интерфейса, к которому привязываются сокеты.
    ///
    /// `None` — привязка не нужна: TUN не поднят, и маршрут по умолчанию
    /// ведёт наружу сам.
    bind_to: Option<IpAddr>,

    /// Разрешатель имён, работающий мимо тоннеля.
    resolver: Arc<dyn Resolver>,
}

impl std::fmt::Debug for SystemDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemDialer")
            .field("bind_to", &self.bind_to)
            .finish()
    }
}

impl SystemDialer {
    /// Выход без привязки к интерфейсу.
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self {
            bind_to: None,
            resolver,
        }
    }

    /// Привязывает исходящие сокеты к указанному адресу.
    pub fn bound_to(mut self, address: IpAddr) -> Self {
        self.bind_to = Some(address);
        self
    }

    /// Адрес, к которому привязываются сокеты.
    pub fn bind_address(&self) -> Option<IpAddr> {
        self.bind_to
    }

    /// Локальный адрес для привязки под семейство удалённого.
    ///
    /// Привязать сокет IPv4 к адресу IPv6 нельзя, и наоборот: если семейства
    /// не совпадают, привязка просто пропускается.
    fn local_for(&self, remote: SocketAddr) -> Option<SocketAddr> {
        let bind = self.bind_to?;
        if bind.is_ipv4() == remote.is_ipv4() {
            Some(SocketAddr::new(bind, 0))
        } else {
            None
        }
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

        let stream = socket.connect(addr).await?;
        // Прокси гоняет мелкие записи — заголовки, подтверждения. Задержка
        // Нейгла копит их и добавляет к каждому запросу лишние миллисекунды.
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }

    async fn bind_udp(&self, local: SocketAddr) -> Result<UdpSocket, ProtocolError> {
        // Привязка к физическому интерфейсу важнее запрошенного адреса:
        // вызывающий указывает семейство, а не конкретный интерфейс.
        let local = self.local_for(local).unwrap_or(local);
        Ok(UdpSocket::bind(local).await?)
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

/// Прямой выход как исходящее направление.
///
/// Оформлен таким же `Outbound`, как любой протокол, и лежит в том же пуле.
/// Благодаря этому у движка нет отдельной ветки «а если напрямую»: решение
/// маршрутизатора всегда превращается в поиск направления по имени, а
/// `direct` — просто одно из имён.
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

    /// Превращает адрес назначения в числовой, разрешая имя при необходимости.
    async fn resolve(&self, target: &SocketAddress) -> Result<SocketAddr, ProtocolError> {
        match &target.host {
            penguin_core::address::Address::Ip(ip) => Ok(SocketAddr::new(*ip, target.port)),
            penguin_core::address::Address::Domain(domain) => {
                let addresses = self.dialer.resolve(domain).await?;
                addresses
                    .into_iter()
                    .next()
                    .map(|ip| SocketAddr::new(ip, target.port))
                    .ok_or_else(|| ProtocolError::Unreachable(domain.clone()))
            }
        }
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
            // Имя разрешается здесь, локально, а не «на той стороне»: та
            // сторона — это и есть сам целевой сервер.
            remote_dns: false,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let addr = self.resolve(target).await?;
        Ok(Box::new(self.dialer.dial_tcp(addr).await?))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        // IPv6-сокет с двойным стеком принял бы и IPv4, но включать его
        // приходится вручную и не везде одинаково. Проще и надёжнее взять
        // IPv4: подавляющее большинство UDP-трафика приложений — он.
        let local = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        let socket = self.dialer.bind_udp(local).await?;
        Ok(Box::new(DirectDatagram {
            socket,
            dialer: Arc::clone(&self.dialer),
        }))
    }
}

/// Датаграммный канал прямого выхода.
struct DirectDatagram {
    socket: UdpSocket,
    dialer: Arc<dyn Dialer>,
}

#[async_trait]
impl ProxyDatagram for DirectDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let addr = match &target.host {
            penguin_core::address::Address::Ip(ip) => SocketAddr::new(*ip, target.port),
            penguin_core::address::Address::Domain(domain) => {
                let addresses = self.dialer.resolve(domain).await?;
                addresses
                    .into_iter()
                    .next()
                    .map(|ip| SocketAddr::new(ip, target.port))
                    .ok_or_else(|| ProtocolError::Unreachable(domain.clone()))?
            }
        };
        self.socket.send_to(&payload, addr).await?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        // 65 535 — наибольшая датаграмма, которую вообще можно получить.
        // Обрезать её было бы порчей данных: приложение не узнает о потере.
        let mut buf = vec![0u8; 65_535];
        let (len, from) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        Ok((Bytes::from(buf), SocketAddress::from(from)))
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
        // Привязать сокет IPv4 к адресу IPv6 нельзя; вместо ошибки соединение
        // просто уходит без привязки.
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

        // Пустой список — это «имени нет», и вызывающий обязан узнать об этом
        // как об ошибке, а не получить успешный ответ без адресов.
        let dialer = SystemDialer::new(Arc::new(Empty));
        assert!(dialer.resolve("nowhere.invalid").await.is_err());
    }
}
