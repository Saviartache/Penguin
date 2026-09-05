//! Направление через сервер Snell.
//!
//! Состояния между вызовами не держит: переиспользование канала у протокола
//! есть (см. [`crate::version`]), но пула соединений здесь нет — каждое
//! подключение открывает своё. Команду переиспользования вторая версия шлёт
//! всё равно: это то, чем она отличается от первой, и сервер ждёт именно её.

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

use crate::config::SnellConfig;
use crate::connector::Connector;
use crate::datagram::{self, SnellDatagram};
use crate::error::SnellResult;
use crate::frame::request;
use crate::stream::SnellStream;

/// Исходящее направление через сервер Snell.
#[derive(Debug)]
pub struct SnellOutbound {
    id: OutboundId,
    connector: Connector,
}

impl SnellOutbound {
    /// Собирает направление. Соединения при этом не открывается.
    pub fn new(id: OutboundId, config: SnellConfig, dialer: Arc<dyn Dialer>) -> SnellResult<Self> {
        let connector = Connector::new(config, dialer)?;

        if connector.config().udp && !connector.config().version.udp() {
            tracing::warn!(
                version = %connector.config().version,
                "UDP разрешён в настройках, но эта версия Snell его не умеет"
            );
        }
        Ok(Self { id, connector })
    }
}

#[async_trait]
impl Outbound for SnellOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        let config = self.connector.config();
        Capabilities {
            // Не то, что стоит в настройках, а то, что выйдет на самом деле:
            // до третьей версии датаграмм у протокола нет вовсе, и обещать их
            // значит потерять запросы DNS молча.
            udp: config.udp_works(),
            // Переиспользование канала у второй версии есть, но пула
            // соединений здесь нет: каждое подключение открывает своё.
            multiplex: false,
            port_hopping: false,
            // Имя уезжает серверу строкой и разрешается на той стороне.
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let command = if self.connector.config().version.reusable() {
            request::CMD_CONNECT_V2
        } else {
            request::CMD_CONNECT
        };

        let header = request::connect(command, target)?;
        let io = self.connector.open(&header).await?;
        Ok(Box::new(SnellStream::new(io.into_stream())))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        let config = self.connector.config();
        datagram::check(config.udp_works(), config.version)?;

        let io = self.connector.open(&request::udp()).await?;
        Ok(Box::new(SnellDatagram::new(io.into_chunks())))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use penguin_transport::obfs::Mode;
    use tokio::net::{TcpStream, UdpSocket};

    use super::*;
    use crate::version::Version;

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

    fn config(version: Version) -> SnellConfig {
        SnellConfig {
            server: "example.com:8443".to_owned(),
            psk: "secret".to_owned(),
            version,
            ..SnellConfig::default()
        }
    }

    fn outbound(config: SnellConfig) -> SnellResult<SnellOutbound> {
        SnellOutbound::new(
            OutboundId::from("тест".to_owned()),
            config,
            Arc::new(NoDialer),
        )
    }

    #[tokio::test]
    async fn udp_is_announced_only_where_it_exists() {
        // Обещать датаграммы там, где их нет, значит терять запросы DNS
        // молча — направление примет их и ничего не сделает.
        for version in [Version::V1, Version::V2] {
            let outbound = outbound(config(version)).expect("собирается");
            assert!(!outbound.capabilities().udp, "{version}");
            assert!(outbound.bind_udp().await.is_err(), "{version}");
        }
        for version in [Version::V3, Version::V4, Version::V5] {
            assert!(
                outbound(config(version))
                    .expect("собирается")
                    .capabilities()
                    .udp,
                "{version}"
            );
        }
    }

    #[tokio::test]
    async fn udp_turned_off_is_refused_and_not_silently_dropped() {
        let outbound = outbound(SnellConfig {
            udp: false,
            ..config(Version::V4)
        })
        .expect("собирается");
        assert!(!outbound.capabilities().udp);
        assert!(outbound.bind_udp().await.is_err());
    }

    #[tokio::test]
    async fn multiplexing_is_not_announced_because_there_is_no_pool() {
        let outbound = outbound(config(Version::V2)).expect("собирается");
        assert!(!outbound.capabilities().multiplex);
        assert!(outbound.capabilities().remote_dns);
        assert!(!outbound.capabilities().port_hopping);
    }

    #[tokio::test]
    async fn bad_settings_are_caught_before_any_connection() {
        assert!(
            outbound(SnellConfig {
                psk: String::new(),
                ..config(Version::V4)
            })
            .is_err()
        );
        assert!(
            outbound(SnellConfig {
                obfs: Mode::None,
                obfs_host: Some("bing.com".to_owned()),
                ..config(Version::V4)
            })
            .is_err()
        );
    }
}
