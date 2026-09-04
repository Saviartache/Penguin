//! Направление через сервер VLESS.
//!
//! Состояния между вызовами не держит: мультиплексирования нет, и каждое
//! подключение — своё соединение со своим заголовком. Собрано заранее то, что
//! дорого собирать заново, — настройки TLS и разобранный адрес сервера.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_core::address::SocketAddress;
use penguin_core::id::OutboundId;
use penguin_proto::capabilities::Capabilities;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;

use crate::config::VlessConfig;
use crate::connector::Connector;
use crate::datagram::VlessDatagram;
use crate::error::{VlessError, VlessResult};
use crate::frame::request::CMD_TCP;

/// Исходящее направление через сервер VLESS.
#[derive(Debug)]
pub struct VlessOutbound {
    id: OutboundId,
    /// Пускать ли UDP.
    udp: bool,
    connector: Arc<Connector>,
}

impl VlessOutbound {
    /// Собирает направление.
    pub fn new(id: OutboundId, config: VlessConfig, dialer: Arc<dyn Dialer>) -> VlessResult<Self> {
        config.validate()?;
        Ok(Self {
            id,
            udp: config.udp,
            connector: Arc::new(Connector::new(&config, dialer)?),
        })
    }

    /// Проверяет, что сервер на месте.
    ///
    /// UUID при этом не проверяется — проверить его нечем: сервер, не узнавший
    /// его, закрывает соединение молча.
    pub async fn verify(&self) -> Result<(), ProtocolError> {
        self.connector.verify().await
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            udp: self.udp,
            // Своё соединение на каждый поток.
            multiplex: false,
            port_hopping: false,
            // Имя уезжает серверу доменом и разрешается на той стороне.
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        self.connector.open(CMD_TCP, target).await
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        if !self.udp {
            return Err(VlessError::UdpDisabled.into());
        }
        Ok(Box::new(VlessDatagram::new(Arc::clone(&self.connector))))
    }
}
