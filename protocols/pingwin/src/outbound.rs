//! Направление: одно соединение на профиль (QUIC или TCP); умершее заменяется на следующем запросе.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use async_trait::async_trait;
use penguin_core::address::SocketAddress;
use penguin_core::id::OutboundId;
use penguin_core::stats::Rtt;
use penguin_proto::capabilities::Capabilities;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;
use tokio::sync::Mutex;

use crate::config::PingwinConfig;
use crate::connection::{Connection, Target};
use crate::error::PingwinResult;

/// Направление Pingwin.
pub struct PingwinOutbound {
    id: OutboundId,
    server: String,
    target: Target,
    dialer: Arc<dyn Dialer>,
    connection: Mutex<Option<Arc<Connection>>>,
    /// В `auto` прошлый раз поднялся TCP.
    prefer_tcp: AtomicBool,
}

impl std::fmt::Debug for PingwinOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PingwinOutbound")
            .field("id", &self.id)
            .field("server", &self.server)
            .finish()
    }
}

impl PingwinOutbound {
    /// Собирает направление. Соединения при этом не открывается.
    pub fn new(
        id: OutboundId,
        config: PingwinConfig,
        dialer: Arc<dyn Dialer>,
    ) -> PingwinResult<Self> {
        config.validate()?;
        let (host, port) = config.endpoint()?;
        Ok(Self {
            target: Target {
                host,
                port,
                server_name: config.server_name()?,
                tls: config.tls()?,
                server_public: config.server_public()?,
                password: config.password.into_bytes(),
                transport: config.transport,
            },
            id,
            server: config.server,
            dialer,
            connection: Mutex::new(None),
            prefer_tcp: AtomicBool::new(false),
        })
    }

    /// Поднимает соединение заранее, чтобы «подключено» не было ложью.
    pub async fn warm_up(&self) -> PingwinResult<()> {
        self.connection().await.map(drop)
    }

    /// Каким переносом поднято соединение: `quic`, `tcp`; `None` — его нет.
    pub async fn transport(&self) -> Option<&'static str> {
        let slot = self.connection.lock().await;
        slot.as_ref()
            .filter(|connection| connection.is_alive())
            .map(|connection| connection.name())
    }

    /// Живое соединение: прежнее или новое (под замком, чтобы не поднять сотню).
    async fn connection(&self) -> PingwinResult<Arc<Connection>> {
        let mut slot = self.connection.lock().await;
        if let Some(alive) = slot.as_ref().filter(|connection| connection.is_alive()) {
            return Ok(Arc::clone(alive));
        }
        let connection = Arc::new(
            Connection::establish(&self.target, self.dialer.as_ref(), &self.prefer_tcp).await?,
        );
        tracing::debug!(
            server = %self.server,
            transport = connection.name(),
            "соединение pingwin поднято"
        );
        *slot = Some(Arc::clone(&connection));
        Ok(connection)
    }
}

#[async_trait]
impl Outbound for PingwinOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
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
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let connection = self.connection().await?;
        Ok(connection
            .open_tcp(target, &self.target, self.dialer.as_ref())
            .await?)
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        let connection = self.connection().await?;
        Ok(connection
            .open_udp(&self.target, self.dialer.as_ref())
            .await?)
    }

    async fn rtt(&self) -> Option<Rtt> {
        let connection = self.connection.lock().await.clone()?;
        if !connection.is_alive() {
            return None;
        }
        let millis = u32::try_from(connection.rtt()?.as_millis()).unwrap_or(u32::MAX);
        Some(Rtt::from_millis(millis))
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        if let Some(connection) = self.connection.lock().await.take() {
            connection.close().await;
        }
        Ok(())
    }
}
