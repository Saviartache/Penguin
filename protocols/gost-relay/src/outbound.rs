//! Направление через сервер GOST Relay.
//!
//! Состояния между вызовами не держит: мультиплексирования нет (`CmdBind`,
//! который бы его дал, здесь не используется), и каждое подключение — своё
//! соединение со своим заголовком, как у VLESS, Trojan и SOCKS5.

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

use crate::config::GostRelayConfig;
use crate::connector::Connector;
use crate::datagram::GostRelayDatagram;
use crate::error::{GostRelayError, GostRelayResult};

/// Исходящее направление через сервер GOST Relay.
#[derive(Debug)]
pub struct GostRelayOutbound {
    id: OutboundId,
    /// Пускать ли UDP.
    udp: bool,
    connector: Arc<Connector>,
}

impl GostRelayOutbound {
    /// Собирает направление.
    pub fn new(
        id: OutboundId,
        config: GostRelayConfig,
        dialer: Arc<dyn Dialer>,
    ) -> GostRelayResult<Self> {
        config.validate()?;
        Ok(Self {
            id,
            udp: config.udp,
            connector: Arc::new(Connector::new(&config, dialer)?),
        })
    }

    /// Проверяет, что сервер на месте.
    ///
    /// Имя и пароль при этом не проверяются: заголовку `CmdConnect` нужен
    /// настоящий целевой адрес, которого на этом шаге ещё нет, — как и у
    /// VLESS, отказ по учётным данным виден только на первом настоящем
    /// соединении.
    pub async fn verify(&self) -> Result<(), ProtocolError> {
        self.connector.verify().await
    }
}

#[async_trait]
impl Outbound for GostRelayOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // Ровно то, что стоит в настройках: соврать здесь означает, что
            // DNS-запросы уйдут в направление, которое их молча потеряет.
            udp: self.udp,
            multiplex: false,
            port_hopping: false,
            // Имя уезжает серверу доменом и разрешается на той стороне.
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        self.connector.open_tcp(target).await
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        if !self.udp {
            return Err(GostRelayError::UdpDisabled.into());
        }
        Ok(Box::new(GostRelayDatagram::new(Arc::clone(
            &self.connector,
        ))))
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

    fn config() -> GostRelayConfig {
        GostRelayConfig {
            server: "example.com:8443".to_owned(),
            username: "bob".to_owned(),
            password: "secret".to_owned(),
            ..GostRelayConfig::default()
        }
    }

    fn outbound(config: GostRelayConfig) -> GostRelayResult<GostRelayOutbound> {
        GostRelayOutbound::new(
            OutboundId::from("тест".to_owned()),
            config,
            Arc::new(NoDialer),
        )
    }

    #[tokio::test]
    async fn capabilities_reflect_the_configured_udp_flag() {
        let capabilities = outbound(config()).expect("собирается").capabilities();
        assert!(capabilities.udp);
        assert!(!capabilities.multiplex);
        assert!(!capabilities.port_hopping);
        assert!(capabilities.remote_dns);

        let capabilities = outbound(GostRelayConfig {
            udp: false,
            ..config()
        })
        .expect("собирается")
        .capabilities();
        assert!(!capabilities.udp);
    }

    #[tokio::test]
    async fn udp_turned_off_is_refused_and_not_silently_dropped() {
        let outbound = outbound(GostRelayConfig {
            udp: false,
            ..config()
        })
        .expect("собирается");
        assert!(outbound.bind_udp().await.is_err());
    }

    #[tokio::test]
    async fn bad_settings_are_caught_before_any_connection() {
        assert!(
            outbound(GostRelayConfig {
                server: "example.com".to_owned(),
                ..config()
            })
            .is_err()
        );
    }
}
