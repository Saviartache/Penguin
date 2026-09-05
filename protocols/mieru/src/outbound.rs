//! Направление через сервер Mieru.
//!
//! Держит пул неявных соединений и задачу уборки простаивающих. Соединений
//! при сборке не открывает: первое поднимается первой сессией, и включённый
//! профиль не платит за это, пока в него не пошли.

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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

use crate::config::MieruConfig;
use crate::connector::Connector;
use crate::error::{MieruError, MieruResult};
use crate::pool::Pool;
use crate::socks5;
use crate::stream::MieruStream;

/// Исходящее направление через сервер Mieru.
pub struct MieruOutbound {
    id: OutboundId,
    pool: Arc<Pool>,
    /// Уборка простаивающих соединений.
    cleanup: JoinHandle<()>,
}

impl std::fmt::Debug for MieruOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MieruOutbound")
            .field("id", &self.id)
            .field("pool", &self.pool)
            .finish()
    }
}

impl MieruOutbound {
    /// Собирает направление.
    pub fn new(id: OutboundId, config: MieruConfig, dialer: Arc<dyn Dialer>) -> MieruResult<Self> {
        config.validate()?;
        let connector = Connector::new(&config, dialer)?;
        let pool = Pool::new(&config, connector);
        let cleanup = tokio::spawn(sweep(Arc::downgrade(&pool), config.idle_check()));

        Ok(Self { id, pool, cleanup })
    }
}

impl Drop for MieruOutbound {
    fn drop(&mut self) {
        self.cleanup.abort();
    }
}

#[async_trait]
impl Outbound for MieruOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // UDP не реализован в этой сборке — см. документ крейта.
            udp: false,
            // Правда: сессия в готовом соединении стоит одного сегмента.
            multiplex: true,
            port_hopping: false,
            // Имя цели уезжает серверу доменом (см. `socks5`) и разрешается
            // на той стороне.
            remote_dns: true,
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let mut stream = self.pool.open().await?;
        handshake_socks5(&mut stream, target).await?;
        Ok(Box::new(stream))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        Err(MieruError::UdpUnsupported.into())
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.pool.close_all().await;
        Ok(())
    }
}

/// Убирает простаивающие соединения, пока направление живо.
async fn sweep(pool: std::sync::Weak<Pool>, every: std::time::Duration) {
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

/// Проходит внутренний SOCKS5 до цели поверх уже открытой сессии Mieru.
///
/// У Mieru нет своего поля адреса назначения (см. документ крейта): адрес
/// передаётся так же, как передал бы его локальный клиент SOCKS5, — и сервер
/// `mita` на другом конце сессии его так и читает.
async fn handshake_socks5(
    stream: &mut MieruStream,
    target: &SocketAddress,
) -> Result<(), ProtocolError> {
    deadline::handshake::<(), MieruError>("SOCKS5 внутри туннеля Mieru", async {
        stream.write_all(&socks5::greeting()).await?;
        stream.flush().await?;

        let mut selection = [0u8; 2];
        stream.read_exact(&mut selection).await?;
        socks5::parse_method_selection(selection)?;

        let request = socks5::connect_request(target)?;
        stream.write_all(&request).await?;
        stream.flush().await?;

        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await?;
        let head = socks5::parse_reply_head(head)?;

        let addr_len = match socks5::fixed_address_len(head.atyp)? {
            Some(len) => len,
            None => {
                let mut len_byte = [0u8; 1];
                stream.read_exact(&mut len_byte).await?;
                usize::from(len_byte[0])
            }
        };
        // Адрес в ответе нам не нужен — только пройти мимо него, не сдвинув
        // границу начала настоящих данных приложения.
        let mut discard = vec![0u8; addr_len + socks5::PORT_LEN];
        stream.read_exact(&mut discard).await?;

        if !socks5::rep_is_success(head.rep) {
            return Err(MieruError::unreachable(socks5::describe_rep(head.rep)));
        }
        Ok(())
    })
    .await
    .map_err(Into::into)
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

    fn outbound(config: MieruConfig) -> MieruResult<MieruOutbound> {
        MieruOutbound::new(
            OutboundId::from("тест".to_owned()),
            config,
            Arc::new(NoDialer),
        )
    }

    fn config() -> MieruConfig {
        MieruConfig {
            server: "example.com:2999".to_owned(),
            username: "alice".to_owned(),
            password: "secret".to_owned(),
            ..MieruConfig::default()
        }
    }

    #[tokio::test]
    async fn a_fresh_outbound_holds_no_connections() {
        let outbound = outbound(config()).expect("собирается");
        assert!(outbound.pool.is_empty());
    }

    #[tokio::test]
    async fn capabilities_do_not_lie_about_udp() {
        let outbound = outbound(config()).expect("собирается");
        let capabilities = outbound.capabilities();
        assert!(!capabilities.udp, "UDP не реализован в этой сборке");
        assert!(capabilities.multiplex);
        assert!(capabilities.remote_dns);
        assert!(!capabilities.port_hopping);
    }

    #[tokio::test]
    async fn udp_is_refused_and_not_silently_dropped() {
        let outbound = outbound(config()).expect("собирается");
        assert!(outbound.bind_udp().await.is_err());
    }

    #[tokio::test]
    async fn bad_settings_are_caught_before_any_connection() {
        assert!(
            outbound(MieruConfig {
                password: String::new(),
                ..config()
            })
            .is_err()
        );
    }
}
