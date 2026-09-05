//! Направление через прокси MASQUE.
//!
//! `CONNECT-UDP` не переносит TCP ни в каком виде — только UDP, адресованный
//! путём запроса (RFC 9298, §2). Поэтому [`MasqueOutbound::connect_tcp`]
//! всегда отказывает: соврать здесь значило бы, что TCP-соединение уходит в
//! направление, которое молча не умеет ничего, кроме UDP (тот же договор,
//! что у `capabilities()`, — см. [`penguin_proto::capabilities::Capabilities`]).

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
            // Одно соединение HTTP/3 несёт сколько угодно каналов
            // `CONNECT-UDP` — рукопожатие QUIC/TLS платится один раз на
            // направление, а не на каждую UDP-ассоциацию.
            multiplex: true,
            port_hopping: false,
            // `target_host` в пути запроса может быть доменным именем — его
            // резолвит прокси (RFC 9298, §2), а не этот клиент.
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

    async fn close(&self) -> Result<(), ProtocolError> {
        self.session.close().await;
        Ok(())
    }
}
