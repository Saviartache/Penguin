//! Направление режима DPI: прямое соединение с планом обхода на первой посылке.

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
}

/// Числовой адрес назначения; имя разрешает сам клиент: «той стороны» нет, есть сайт.
pub(crate) async fn resolve(
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
            remote_dns: false,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        // Имя даёт точки разреза (fake-IP или `engine::sniff`); без него посылка уходит целиком
        let host = target.host.as_domain().map(str::to_owned);
        if host.is_none() {
            tracing::debug!(%target, "имени узла нет — резать посылку не по чему");
        }
        let addr = resolve(&*self.dialer, target).await?;
        let stream = self.dialer.dial_tcp(addr).await?;
        Ok(Box::new(FirstFlight::new(stream, self.plan.clone(), host)))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        // IPv4: двойной стек включается не везде одинаково
        let local = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        let socket = self.dialer.bind_udp(local).await?;
        Ok(Box::new(DirectDatagram::new(
            socket,
            Arc::clone(&self.dialer),
        )))
    }
}
