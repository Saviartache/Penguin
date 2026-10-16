//! Направление через сервер naive поверх HTTP/2.

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

use crate::config::NaiveConfig;
use crate::connect;
use crate::error::{NaiveError, NaiveResult};
use crate::padding::{self, PaddedStream};
use crate::transport::h2::{self as transport, Http2Transport};
use penguin_transport::h2::H2Stream;

/// Направление через сервер naive поверх HTTP/2.
pub struct NaiveHttp2Outbound {
    id: OutboundId,
    config: NaiveConfig,
    transport: Http2Transport,
}

impl std::fmt::Debug for NaiveHttp2Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NaiveHttp2Outbound")
            .field("id", &self.id)
            .field("config", &self.config)
            .finish()
    }
}

impl NaiveHttp2Outbound {
    /// Устанавливает соединение; каждый `connect_tcp` — свой поток `CONNECT` в нём.
    pub async fn connect(
        id: OutboundId,
        config: NaiveConfig,
        dialer: Arc<dyn Dialer>,
    ) -> NaiveResult<Self> {
        config.validate()?;
        let (host, port) = config.endpoint()?;
        let transport = transport::connect(&config, dialer.as_ref(), &host, port).await?;
        Ok(Self {
            id,
            config,
            transport,
        })
    }

    async fn open(&self, target: &SocketAddress) -> NaiveResult<Box<dyn ProxyStream>> {
        let mut send_request = self
            .transport
            .send_request
            .clone()
            .ready()
            .await
            .map_err(|e| NaiveError::Disconnected(e.to_string()))?;

        let request = connect::request(target, self.config.credentials())?;
        let (response, send_stream) = send_request
            .send_request(request, false)
            .map_err(|e| NaiveError::transport(format!("запрос CONNECT не отправлен: {e}")))?;

        let stream = connect::perform(target, async {
            let response = response
                .await
                .map_err(|e| NaiveError::Disconnected(e.to_string()))?;
            let status = response.status().as_u16();
            let mode = padding::negotiate_h2(response.headers());
            let recv_stream = response.into_body();
            let io = PaddedStream::new(H2Stream::new(send_stream, recv_stream), mode);
            Ok((status, io))
        })
        .await?;

        Ok(Box::new(stream))
    }
}

#[async_trait]
impl Outbound for NaiveHttp2Outbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL_HTTP2
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
        self.transport.is_alive()
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.transport.shutdown();
        Ok(())
    }
}
