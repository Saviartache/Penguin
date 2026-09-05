//! Направление через сервер SSH: канал `direct-tcpip` вместо своего протокола.
//!
//! Соединение при сборке не поднимается: первый канал заводит первое, и
//! рукопожатие SSH платится не при включении профиля, а когда в него правда
//! пошли — как у остальных протоколов с постоянным соединением.

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

use crate::config::SshConfig;
use crate::error::SshResult;
use crate::pool::SshPool;

/// Исходящее направление через сервер SSH.
#[derive(Debug)]
pub struct SshOutbound {
    id: OutboundId,
    pool: Arc<SshPool>,
}

impl SshOutbound {
    /// Собирает направление.
    pub fn new(id: OutboundId, config: SshConfig, dialer: Arc<dyn Dialer>) -> SshResult<Self> {
        Ok(Self {
            id,
            pool: Arc::new(SshPool::new(config, dialer)?),
        })
    }
}

#[async_trait]
impl Outbound for SshOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // У `direct-tcpip` датаграмм не бывает: соврать здесь значит
            // потерять запросы DNS молча.
            udp: false,
            // Каналы живут в одном соединении SSH, поднятом один раз.
            multiplex: true,
            port_hopping: false,
            // Имя уезжает серверу как есть, и разрешает его сервер.
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let stream = self.pool.open(target).await?;
        Ok(Box::new(stream))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        Err(ProtocolError::Unsupported("UDP"))
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.pool.close_all().await;
        Ok(())
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

    const FINGERPRINT: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";

    fn config() -> SshConfig {
        SshConfig {
            server: "example.com:22".to_owned(),
            username: "penguin".to_owned(),
            password: Some("secret".to_owned()),
            host_fingerprint: FINGERPRINT.to_owned(),
            ..SshConfig::default()
        }
    }

    fn outbound(config: SshConfig) -> SshResult<SshOutbound> {
        SshOutbound::new(
            OutboundId::from("тест".to_owned()),
            config,
            Arc::new(NoDialer),
        )
    }

    #[tokio::test]
    async fn multiplexing_is_announced_because_it_is_real() {
        let capabilities = outbound(config()).expect("собирается").capabilities();
        assert!(capabilities.multiplex);
        assert!(capabilities.remote_dns);
        assert!(!capabilities.port_hopping);
    }

    #[tokio::test]
    async fn udp_is_never_announced() {
        // `direct-tcpip` не умеет датаграмм: соврать здесь значит потерять
        // запросы DNS молча.
        let outbound = outbound(config()).expect("собирается");
        assert!(!outbound.capabilities().udp);
        assert!(outbound.bind_udp().await.is_err());
    }

    #[tokio::test]
    async fn bad_settings_are_caught_before_any_connection() {
        assert!(
            outbound(SshConfig {
                username: String::new(),
                ..config()
            })
            .is_err()
        );
    }

    #[tokio::test]
    async fn closing_a_fresh_outbound_does_nothing_bad() {
        let outbound = outbound(config()).expect("собирается");
        outbound.close().await.expect("закрывается без сети");
    }
}
