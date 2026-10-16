//! Направление через сервер naive поверх HTTP/3.

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
use penguin_transport::TransportError;
use penguin_transport::h3::code::H3_NO_ERROR;

use crate::config::NaiveConfig;
use crate::connect;
use crate::error::NaiveResult;
use crate::padding::{self, PaddedStream};
use crate::transport::h3::{self as transport, Http3Transport};

/// Направление через сервер naive поверх HTTP/3.
pub struct NaiveHttp3Outbound {
    id: OutboundId,
    config: NaiveConfig,
    transport: Http3Transport,
}

impl std::fmt::Debug for NaiveHttp3Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NaiveHttp3Outbound")
            .field("id", &self.id)
            .field("config", &self.config)
            .finish()
    }
}

impl NaiveHttp3Outbound {
    /// Устанавливает соединение; каждый `connect_tcp` — свой поток `CONNECT` в нём.
    pub async fn connect(
        id: OutboundId,
        config: NaiveConfig,
        dialer: Arc<dyn Dialer>,
    ) -> NaiveResult<Self> {
        config.validate()?;
        let transport = transport::connect(&config, dialer.as_ref()).await?;
        Ok(Self {
            id,
            config,
            transport,
        })
    }

    async fn open(&self, target: &SocketAddress) -> NaiveResult<Box<dyn ProxyStream>> {
        let request = connect::request_h3(target, self.config.credentials());
        let stream = connect::perform(target, async {
            let mut stream = self
                .transport
                .h3
                .send_request(&request)
                .await
                .map_err(TransportError::from)?;
            let response = stream.response().await.map_err(TransportError::from)?;
            let mode = padding::negotiate_h3(&response);
            Ok((response.status(), PaddedStream::new(stream, mode)))
        })
        .await?;
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl Outbound for NaiveHttp3Outbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL_HTTP3
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            udp: false,
            multiplex: true,
            port_hopping: false,
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        self.open(target).await.map_err(Into::into)
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        Err(ProtocolError::Unsupported("UDP"))
    }

    fn is_alive(&self) -> bool {
        self.transport.link.is_alive()
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.transport.link.close(H3_NO_ERROR, b"").await;
        Ok(())
    }
}
