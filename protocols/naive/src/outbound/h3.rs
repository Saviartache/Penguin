//! Направление через сервер naive поверх HTTP/3.

use std::net::SocketAddr;
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

use crate::config::NaiveConfig;
use crate::connect;
use crate::error::{NaiveError, NaiveResult};
use crate::padding::{self, PaddedStream};
use crate::stream::h3::H3Stream;
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
    /// Устанавливает соединение с сервером и держит его открытым.
    pub async fn connect(
        id: OutboundId,
        config: NaiveConfig,
        dialer: Arc<dyn Dialer>,
    ) -> NaiveResult<Self> {
        config.validate()?;
        let (host, port) = config.endpoint()?;
        let server_name = config.server_name()?;
        let server = resolve_server(&host, port, dialer.as_ref()).await?;

        let transport = transport::connect(&config, dialer.as_ref(), server, &server_name).await?;
        Ok(Self {
            id,
            config,
            transport,
        })
    }

    async fn open(&self, target: &SocketAddress) -> NaiveResult<Box<dyn ProxyStream>> {
        let mut send_request = self.transport.send_request.clone();
        let request = connect::request(target, self.config.credentials())?;

        let stream = connect::perform(target, async {
            let mut request_stream = send_request
                .send_request(request)
                .await
                .map_err(|e| NaiveError::Disconnected(e.to_string()))?;

            let response = request_stream
                .recv_response()
                .await
                .map_err(|e| NaiveError::Disconnected(e.to_string()))?;
            let status = response.status().as_u16();
            let mode = padding::negotiate(response.headers());

            let (send_half, recv_half) = request_stream.split();
            let io = PaddedStream::new(H3Stream::new(send_half, recv_half), mode);
            Ok((status, io))
        })
        .await?;

        Ok(Box::new(stream))
    }
}

/// Разрешает имя сервера мимо тоннеля.
///
/// HTTP/2 получает это бесплатно от `penguin_proto::connect::dial`, но QUIC
/// поднимается не поверх `TcpStream`, а поверх голого UDP-сокета — адрес
/// нужен раньше, до того как `Dialer` вообще появляется в игре.
async fn resolve_server(host: &Address, port: u16, dialer: &dyn Dialer) -> NaiveResult<SocketAddr> {
    let addresses = penguin_proto::connect::resolve(dialer, host, port)
        .await
        .map_err(|e| NaiveError::Disconnected(e.to_string()))?;
    addresses
        .into_iter()
        .next()
        .ok_or_else(|| NaiveError::transport(format!("`{host}` не разрешился ни в один адрес")))
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
            // См. комментарий в `outbound::h2` — то же самое верно и здесь:
            // у CONNECT нет датаграмм ни в каком виде.
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

    async fn close(&self) -> Result<(), ProtocolError> {
        self.transport
            .connection
            .close(0u32.into(), b"closed by client");
        // Ждать эндпойнт обязательно: без этого прощальный пакет может не
        // успеть уйти, и сервер продержит сессию до истечения тайм-аута.
        // Задача, качающая HTTP/3, останавливается сама — она ждёт закрытия
        // именно этого соединения.
        self.transport.endpoint.wait_idle().await;
        Ok(())
    }
}
