//! Направление через сервер VMess.
//!
//! Состояния между вызовами не держит: мультиплексирования нет, и каждое
//! подключение — своё соединение со своим заголовком и своими ключами тела.

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

use crate::config::VmessConfig;
use crate::connector::Connector;
use crate::datagram::VmessDatagram;
use crate::error::VmessError;
use crate::frame::request::CMD_TCP;

/// Исходящее направление через сервер VMess.
#[derive(Debug)]
pub struct VmessOutbound {
    id: OutboundId,
    udp: bool,
    connector: Arc<Connector>,
}

impl VmessOutbound {
    /// Собирает направление.
    pub fn new(
        id: OutboundId,
        config: VmessConfig,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Self, ProtocolError> {
        config.validate()?;
        Ok(Self {
            id,
            udp: config.udp,
            connector: Arc::new(Connector::new(&config, dialer)?),
        })
    }

    /// Проверяет, что сервер на месте.
    ///
    /// Идентичность при этом не проверяется — проверить её нечем: сервер, не
    /// узнавший опознавателя заголовка ни у одного пользователя, закрывает
    /// соединение молча.
    pub async fn verify(&self) -> Result<(), ProtocolError> {
        self.connector.verify().await
    }
}

#[async_trait]
impl Outbound for VmessOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            udp: self.udp,
            multiplex: false,
            port_hopping: false,
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
            return Err(VmessError::UdpDisabled.into());
        }
        Ok(Box::new(VmessDatagram::new(Arc::clone(&self.connector))))
    }
}
