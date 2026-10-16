//! Направление: одно соединение HTTP/3 на профиль, потоки внутри него.
//!
//! Одного хватает: у QUIC каждый поток теряет пакеты сам за себя, и потеря
//! на одной вкладке браузера не останавливает остальные. Умершее соединение
//! не воскрешается — на следующем же запросе поднимается новое.

use std::sync::Arc;

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
use crate::error::PingwinResult;
use crate::session::{Session, Target};

/// Направление Pingwin.
pub struct PingwinOutbound {
    id: OutboundId,
    server: String,
    target: Target,
    dialer: Arc<dyn Dialer>,
    session: Mutex<Option<Arc<Session>>>,
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
            },
            id,
            server: config.server,
            dialer,
            session: Mutex::new(None),
        })
    }

    /// Поднимает соединение, ничего через него не открывая.
    ///
    /// Зовётся при подключении профиля: пока сюда не сходили, никто не знает,
    /// отвечает ли сервер, а окно уже написало бы «подключено».
    pub async fn warm_up(&self) -> PingwinResult<()> {
        self.session().await.map(drop)
    }

    /// Живое соединение: прежнее или новое.
    ///
    /// Под замком: сотня запросов, пришедших разом, подняла бы сотню
    /// соединений вместо одного.
    async fn session(&self) -> PingwinResult<Arc<Session>> {
        let mut slot = self.session.lock().await;
        if let Some(alive) = slot.as_ref().filter(|session| session.is_alive()) {
            return Ok(Arc::clone(alive));
        }
        let session = Arc::new(Session::establish(&self.target, self.dialer.as_ref()).await?);
        tracing::debug!(server = %self.server, "соединение pingwin поднято");
        *slot = Some(Arc::clone(&session));
        Ok(session)
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
        let session = self.session().await?;
        Ok(Box::new(session.open_tcp(target).await?))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        let session = self.session().await?;
        Ok(Box::new(session.open_udp().await?))
    }

    async fn rtt(&self) -> Option<Rtt> {
        // Открытие потока меряет ноль — оно ничего не ждёт. QUIC же меряет
        // оборот на каждом подтверждении.
        let session = self.session.lock().await.clone()?;
        if !session.is_alive() {
            return None;
        }
        let millis = u32::try_from(session.rtt().as_millis()).unwrap_or(u32::MAX);
        Some(Rtt::from_millis(millis))
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        if let Some(session) = self.session.lock().await.take() {
            session.close().await;
        }
        Ok(())
    }
}
