//! Направление режима DPI: то же прямое соединение, но с планом на первой
//! посылке.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use penguin_core::address::{Address, SocketAddress};
use penguin_core::id::OutboundId;
use penguin_proto::capabilities::Capabilities;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;
use penguin_transport::desync::Desync;

use crate::config::DpiConfig;
use crate::datagram::DirectDatagram;
use crate::flight::FirstFlight;

/// Прямой выход, обходящий DPI первой посылкой.
pub struct DpiOutbound {
    id: OutboundId,
    plan: Desync,
    dialer: Arc<dyn Dialer>,
}

impl std::fmt::Debug for DpiOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpiOutbound")
            .field("id", &self.id)
            .field("plan", &self.plan)
            .finish_non_exhaustive()
    }
}

impl DpiOutbound {
    /// Собирает направление из проверенных настроек.
    pub fn new(
        id: OutboundId,
        config: &DpiConfig,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            id,
            plan: config.plan()?,
            dialer,
        })
    }

    /// Превращает адрес назначения в числовой, разрешая имя при необходимости.
    ///
    /// Разрешает его **этот** клиент, а не «та сторона»: той стороны здесь
    /// нет, есть сам сайт.
    async fn resolve(&self, target: &SocketAddress) -> Result<SocketAddr, ProtocolError> {
        match &target.host {
            Address::Ip(ip) => Ok(SocketAddr::new(*ip, target.port)),
            Address::Domain(domain) => self
                .dialer
                .resolve(domain)
                .await?
                .into_iter()
                .next()
                .map(|ip| SocketAddr::new(ip, target.port))
                .ok_or_else(|| ProtocolError::Unreachable(domain.clone())),
        }
    }
}

#[async_trait]
impl Outbound for DpiOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            udp: true,
            multiplex: false,
            port_hopping: false,
            // Имя разрешается здесь: «та сторона» — это и есть сам сайт.
            remote_dns: false,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        // Имя нужно обходу: от него считаются точки разреза. Его приносит
        // либо обратное отображение fake-IP, либо опознание в потоке
        // (`engine::sniff`); нет имени — режущих ориентиров тоже нет, и
        // посылка уйдёт целиком.
        let host = target.host.as_domain().map(str::to_owned);
        if host.is_none() {
            // Не ошибка, но и не обход: соединение уйдёт как обычное. Сказать
            // об этом надо здесь — иначе «режим включён, а сайт не открылся»
            // ищут в сети.
            tracing::debug!(%target, "имени узла нет — резать посылку не по чему");
        }
        let addr = self.resolve(target).await?;
        let stream = self.dialer.dial_tcp(addr).await?;
        Ok(Box::new(FirstFlight::new(stream, self.plan.clone(), host)))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        // IPv6-сокет с двойным стеком принял бы и IPv4, но включать его
        // приходится вручную и не везде одинаково. Проще и надёжнее взять
        // IPv4: подавляющее большинство UDP-трафика приложений — он.
        let local = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        let socket = self.dialer.bind_udp(local).await?;
        Ok(Box::new(DirectDatagram::new(
            socket,
            Arc::clone(&self.dialer),
        )))
    }
}
