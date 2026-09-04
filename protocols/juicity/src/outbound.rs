//! Направление через сервер Juicity.
//!
//! Соединений при сборке не открывает: первое поднимается первым потоком, и
//! рукопожатие QUIC платится не при включении профиля, а тогда, когда в него
//! правда пошли.

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
use penguin_transport::deadline;

use crate::config::JuicityConfig;
use crate::datagram::JuicityDatagram;
use crate::error::{JuicityError, JuicityResult};
use crate::frame::proxy;
use crate::pool::LinkPool;
use crate::stream::JuicityStream;

/// Исходящее направление через сервер Juicity.
#[derive(Debug)]
pub struct JuicityOutbound {
    id: OutboundId,
    pool: Arc<LinkPool>,
}

impl JuicityOutbound {
    /// Собирает направление.
    pub fn new(
        id: OutboundId,
        config: JuicityConfig,
        dialer: Arc<dyn Dialer>,
    ) -> JuicityResult<Self> {
        Ok(Self {
            id,
            pool: Arc::new(LinkPool::new(config, dialer)?),
        })
    }
}

#[async_trait]
impl Outbound for JuicityOutbound {
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
            udp: self.pool.config().udp,
            // Поток в готовом соединении QUIC стоит одного кадра.
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
        let header = proxy::header(proxy::NET_TCP, target)?;

        // Заголовок уходит сразу и отдельно. Эталон склеивает его с первыми
        // данными и, если их нет, досылает через 100-300 мс — иначе сервер,
        // который должен заговорить первым, не дождётся команды. Отдельно
        // проще и даёт серверу начать соединение раньше; спецификация
        // разрешает оба порядка.
        deadline::handshake::<_, JuicityError>("заголовок запроса Juicity", async {
            stream
                .send
                .write_all(&header)
                .await
                .map_err(|e| JuicityError::disconnected(e.to_string()))?;
            Ok(())
        })
        .await?;

        Ok(Box::new(JuicityStream::new(stream)))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        if !self.pool.config().udp {
            return Err(JuicityError::UdpDisabled.into());
        }
        Ok(Box::new(JuicityDatagram::new(Arc::clone(&self.pool))))
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

    const TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

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

    fn config() -> JuicityConfig {
        JuicityConfig {
            server: "example.com:443".to_owned(),
            uuid: TEXT.parse().expect("разбирается"),
            password: "secret".to_owned(),
            ..JuicityConfig::default()
        }
    }

    fn outbound(config: JuicityConfig) -> JuicityResult<JuicityOutbound> {
        JuicityOutbound::new(
            OutboundId::from("тест".to_owned()),
            config,
            Arc::new(NoDialer),
        )
    }

    #[tokio::test]
    async fn a_fresh_outbound_holds_no_connections() {
        let outbound = outbound(config()).expect("собирается");
        assert!(outbound.pool.is_empty().await);
    }

    #[tokio::test]
    async fn multiplexing_is_announced_because_it_is_real() {
        let capabilities = outbound(config()).expect("собирается").capabilities();
        assert!(capabilities.multiplex);
        assert!(capabilities.udp);
        assert!(capabilities.remote_dns);
        assert!(!capabilities.port_hopping);
    }

    #[tokio::test]
    async fn udp_turned_off_is_refused_and_not_silently_dropped() {
        let outbound = outbound(JuicityConfig {
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
            outbound(JuicityConfig {
                uuid: penguin_core::uuid::Uuid::default(),
                ..config()
            })
            .is_err()
        );
    }
}
