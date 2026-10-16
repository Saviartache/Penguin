//! Направление через прокси MASQUE.
//!
//! Только UDP: [`MasqueOutbound::connect_tcp`] всегда отказывает.

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

use crate::config::MasqueConfig;
use crate::datagram::MasqueDatagram;
use crate::error::MasqueResult;
use crate::session::Session;

/// Направление через прокси MASQUE (`CONNECT-UDP`, RFC 9298).
pub struct MasqueOutbound {
    id: OutboundId,
    session: Arc<Session>,
}

impl std::fmt::Debug for MasqueOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasqueOutbound")
            .field("id", &self.id)
            .field("session", &self.session)
            .finish()
    }
}

impl MasqueOutbound {
    /// Устанавливает соединение с прокси и держит его открытым.
    pub async fn connect(
        id: OutboundId,
        config: MasqueConfig,
        dialer: Arc<dyn Dialer>,
    ) -> MasqueResult<Self> {
        let session = Session::connect(&config, dialer.as_ref()).await?;
        Ok(Self {
            id,
            session: Arc::new(session),
        })
    }
}

#[async_trait]
impl Outbound for MasqueOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL_MASQUE
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            udp: true,
            multiplex: true,
            port_hopping: false,
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        _target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        Err(ProtocolError::Unsupported("TCP"))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        Ok(Box::new(MasqueDatagram::new(Arc::clone(&self.session))))
    }

    fn is_alive(&self) -> bool {
        self.session.is_alive()
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.session.close().await;
        Ok(())
    }
}
