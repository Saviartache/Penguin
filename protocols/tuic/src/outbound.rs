//! Направление через сервер TUIC: соединение постоянное, при обрыве
//! `connect_tcp` отвечает `Disconnected`, а переподнимает его пул направлений.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_core::address::SocketAddress;
use penguin_core::id::OutboundId;
use penguin_proto::capabilities::Capabilities;
use penguin_proto::connect;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;

use crate::config::TuicConfig;
use crate::datagram::TuicDatagram;
use crate::error::{TuicError, TuicResult};
use crate::session::Session;
use crate::stream::TuicStream;
use crate::transport;

/// Исходящее направление через сервер TUIC.
#[derive(Debug)]
pub struct TuicOutbound {
    id: OutboundId,
    udp: bool,
    session: Arc<Session>,
}

impl TuicOutbound {
    /// Поднимает соединение и представляется серверу.
    pub async fn connect(
        id: OutboundId,
        config: TuicConfig,
        dialer: Arc<dyn Dialer>,
    ) -> TuicResult<Self> {
        config.validate()?;
        let (host, port) = config.endpoint()?;

        let server_name = match config.tls.sni.as_deref().map(str::trim) {
            Some(sni) if !sni.is_empty() => sni.to_owned(),
            _ => host.to_string(),
        };

        let addresses = connect::resolve(&*dialer, &host, port)
            .await
            .map_err(|e| TuicError::Disconnected(e.to_string()))?;

        let mut last = None;
        for address in addresses {
            match transport::connect(&config, &*dialer, address, &server_name).await {
                Ok(transport) => {
                    let session = Session::start(transport, &config).await?;
                    return Ok(Self {
                        id,
                        udp: config.udp,
                        session,
                    });
                }
                Err(err) => last = Some(err),
            }
        }

        Err(last.unwrap_or_else(|| {
            TuicError::Disconnected(format!("до `{host}:{port}` не нашлось ни одного адреса"))
        }))
    }
}

#[async_trait]
impl Outbound for TuicOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            udp: self.udp,
            multiplex: true,
            port_hopping: false,
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        if !self.session.is_alive() {
            return Err(TuicError::Disconnected("соединение QUIC закрыто".to_owned()).into());
        }
        let (send, recv) = self.session.open(target).await?;
        Ok(Box::new(TuicStream::new(send, recv)))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        if !self.udp {
            return Err(ProtocolError::Unsupported("UDP"));
        }
        if !self.session.is_alive() {
            return Err(TuicError::Disconnected("соединение QUIC закрыто".to_owned()).into());
        }
        Ok(Box::new(TuicDatagram::new(Arc::clone(&self.session))))
    }

    fn is_alive(&self) -> bool {
        self.session.is_alive()
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.session.close();
        Ok(())
    }
}
