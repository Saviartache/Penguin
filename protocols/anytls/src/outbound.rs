//! Направление через сервер AnyTLS.
//!
//! Держит пул сессий и задачу уборки. Соединений при сборке не открывает:
//! первая сессия поднимается первым потоком, и рукопожатие TLS платится не
//! при включении профиля, а тогда, когда в него правда пошли.

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
use penguin_transport::addr::socks;
use penguin_transport::deadline;
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;

use crate::config::AnyTlsConfig;
use crate::connector::Connector;
use crate::datagram::AnyTlsDatagram;
use crate::error::{AnyTlsError, AnyTlsResult};
use crate::pool::SessionPool;

/// Исходящее направление через сервер AnyTLS.
pub struct AnyTlsOutbound {
    id: OutboundId,
    config: AnyTlsConfig,
    pool: Arc<SessionPool>,
    /// Уборка простаивающих сессий.
    cleanup: JoinHandle<()>,
}

impl std::fmt::Debug for AnyTlsOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsOutbound")
            .field("id", &self.id)
            .field("config", &self.config)
            .field("pool", &self.pool)
            .finish()
    }
}

impl AnyTlsOutbound {
    /// Собирает направление.
    pub fn new(
        id: OutboundId,
        config: AnyTlsConfig,
        dialer: Arc<dyn Dialer>,
    ) -> AnyTlsResult<Self> {
        config.validate()?;
        let pool = SessionPool::new(&config, Connector::new(&config, dialer)?);
        let cleanup = tokio::spawn(sweep(Arc::downgrade(&pool), config.idle_check()));

        Ok(Self {
            id,
            config,
            pool,
            cleanup,
        })
    }
}

impl Drop for AnyTlsOutbound {
    fn drop(&mut self) {
        self.cleanup.abort();
    }
}

#[async_trait]
impl Outbound for AnyTlsOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // Ровно то, что стоит в настройках: соврать здесь означает, что
            // запросы DNS уйдут в направление, которое их молча потеряет.
            udp: self.config.udp,
            // Здесь это правда: поток в готовой сессии стоит одного кадра.
            multiplex: true,
            port_hopping: false,
            // Имя уезжает серверу доменом и разрешается на той стороне.
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let mut stream = self.pool.open().await?;

        // Адрес назначения — первое, что уходит в поток. Ответа на него нет:
        // сервер либо подтвердит открытие отдельным кадром, либо промолчит.
        let mut header = Vec::new();
        socks::encode(target, &mut header).map_err(AnyTlsError::from)?;

        deadline::handshake::<_, AnyTlsError>("адрес назначения AnyTLS", async {
            stream.write_all(&header).await?;
            stream.flush().await?;
            Ok(())
        })
        .await?;

        Ok(Box::new(stream))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        if !self.config.udp {
            return Err(AnyTlsError::UdpDisabled.into());
        }
        Ok(Box::new(AnyTlsDatagram::new(Arc::clone(&self.pool))))
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.pool.close_all();
        Ok(())
    }
}

/// Убирает простаивающие сессии, пока направление живо.
async fn sweep(pool: std::sync::Weak<SessionPool>, every: std::time::Duration) {
    let mut ticker = tokio::time::interval(every);
    // Первый тик приходит сразу; пропускаем его — убирать ещё нечего.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let Some(pool) = pool.upgrade() else {
            return;
        };
        pool.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use tokio::net::{TcpStream, UdpSocket};

    use super::*;

    /// Звонящий, который никуда не звонит.
    #[derive(Debug)]
    struct NoDialer;

    #[async_trait]
    impl Dialer for NoDialer {
        async fn dial_tcp(&self, _addr: SocketAddr) -> Result<TcpStream, ProtocolError> {
            Err(ProtocolError::Unsupported("сеть в тесте"))
        }

        async fn bind_udp(&self, _local: SocketAddr) -> Result<UdpSocket, ProtocolError> {
            Err(ProtocolError::Unsupported("сеть в тесте"))
        }

        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, ProtocolError> {
            Err(ProtocolError::Unsupported("сеть в тесте"))
        }
    }

    fn outbound(config: AnyTlsConfig) -> AnyTlsResult<AnyTlsOutbound> {
        AnyTlsOutbound::new(
            OutboundId::from("тест".to_owned()),
            config,
            Arc::new(NoDialer),
        )
    }

    fn config() -> AnyTlsConfig {
        AnyTlsConfig {
            server: "example.com:443".to_owned(),
            password: "secret".to_owned(),
            ..AnyTlsConfig::default()
        }
    }

    #[tokio::test]
    async fn a_fresh_outbound_holds_no_connections() {
        // Рукопожатие TLS платится тогда, когда в направление пошли, а не
        // когда его включили: иначе профиль в списке стоил бы соединения.
        let outbound = outbound(config()).expect("собирается");
        assert!(outbound.pool.is_empty());
    }

    #[tokio::test]
    async fn multiplexing_is_announced_because_it_is_real() {
        let outbound = outbound(config()).expect("собирается");
        let capabilities = outbound.capabilities();
        assert!(capabilities.multiplex);
        assert!(capabilities.udp);
        assert!(capabilities.remote_dns);
        assert!(!capabilities.port_hopping);
    }

    #[tokio::test]
    async fn udp_turned_off_is_refused_and_not_silently_dropped() {
        let outbound = outbound(AnyTlsConfig {
            udp: false,
            ..config()
        })
        .expect("собирается");
        assert!(!outbound.capabilities().udp);
        assert!(outbound.bind_udp().await.is_err());
    }

    #[tokio::test]
    async fn bad_settings_are_caught_before_any_connection() {
        assert!(
            outbound(AnyTlsConfig {
                password: String::new(),
                ..config()
            })
            .is_err()
        );
    }
}
