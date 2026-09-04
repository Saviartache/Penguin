//! Набор соединений QUIC одного направления.
//!
//! # Зачем не одно
//!
//! У QUIC есть предел одновременно открытых потоков, и спецификация Juicity
//! требует заводить новое соединение, когда он близко (см. [`crate::link`]).
//! Поэтому направление держит не одно соединение, а список: новые потоки
//! уходят в последнее годное, а исчерпавшие себя доживают со своими потоками
//! и умирают вместе с последним из них.
//!
//! # Замок держится через подключение
//!
//! Нарочно: десяток соединений приложения, стартовавших разом на пустом
//! списке, иначе подняли бы десяток соединений QUIC, каждое со своим
//! рукопожатием TLS. Пока одно поднимается, остальные ждут его — и получают
//! готовое.

use std::sync::Arc;

use penguin_core::address::Address;
use penguin_proto::connect;
use penguin_proto::dialer::Dialer;
use tokio::sync::Mutex;

use crate::config::JuicityConfig;
use crate::error::{JuicityError, JuicityResult};
use crate::link::Link;

/// Соединения одного направления.
pub struct LinkPool {
    config: JuicityConfig,
    dialer: Arc<dyn Dialer>,
    /// Хост сервера, разобранный один раз при сборке.
    host: Address,
    /// Порт сервера.
    port: u16,
    /// Имя для TLS.
    server_name: String,
    links: Mutex<Vec<Arc<Link>>>,
}

impl std::fmt::Debug for LinkPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkPool")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("server_name", &self.server_name)
            .finish()
    }
}

impl LinkPool {
    /// Заводит набор. Соединений при этом не открывается.
    pub fn new(config: JuicityConfig, dialer: Arc<dyn Dialer>) -> JuicityResult<Self> {
        config.validate()?;
        let (host, port) = config.endpoint()?;

        // Имя для TLS берётся из настроек, а если его там нет — из адреса
        // сервера. Тот же порядок, что у остальных протоколов.
        let server_name = match config.tls.sni.as_deref().map(str::trim) {
            Some(sni) if !sni.is_empty() => sni.to_owned(),
            _ => host.to_string(),
        };

        Ok(Self {
            config,
            dialer,
            host,
            port,
            server_name,
            links: Mutex::new(Vec::new()),
        })
    }

    /// Настройки направления.
    pub fn config(&self) -> &JuicityConfig {
        &self.config
    }

    /// Открывает двусторонний поток.
    ///
    /// Соединение, выбранное из списка, могло умереть, пока его выбирали:
    /// сервер закрывает их по своему сроку, и узнаём мы об этом только при
    /// попытке. Поэтому неудача — повод попробовать ещё раз на свежем, а не
    /// показывать человеку ошибку.
    pub async fn open(&self) -> JuicityResult<Stream> {
        let link = self.take_or_create().await?;
        match link.open().await {
            Ok((send, recv)) => Ok(Stream { link, send, recv }),
            Err(err) => {
                tracing::debug!(%err, "соединение из набора не годится");
                self.forget(&link).await;

                let link = self.take_or_create().await?;
                let (send, recv) = link.open().await?;
                Ok(Stream { link, send, recv })
            }
        }
    }

    /// Сколько соединений держится. Нужно журналу и тестам.
    pub async fn len(&self) -> usize {
        self.links.lock().await.len()
    }

    /// Есть ли хоть одно соединение.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Закрывает все соединения направления.
    ///
    /// Те, на которых ещё живут потоки, умрут вместе с последним из них: их
    /// держит не только набор.
    pub async fn close_all(&self) {
        self.links.lock().await.clear();
    }

    /// Берёт годное соединение или поднимает новое.
    async fn take_or_create(&self) -> JuicityResult<Arc<Link>> {
        let mut links = self.links.lock().await;

        // Умершие и исчерпавшие себя из списка уходят: держать их означало бы
        // держать эндпойнт, у которого больше не будет потоков.
        links.retain(|link| link.usable());
        if let Some(link) = links.last() {
            return Ok(Arc::clone(link));
        }

        let link = self.dial().await?;
        links.push(Arc::clone(&link));
        Ok(link)
    }

    /// Убирает соединение из набора.
    async fn forget(&self, gone: &Arc<Link>) {
        self.links
            .lock()
            .await
            .retain(|link| !Arc::ptr_eq(link, gone));
    }

    /// Поднимает соединение, перебирая адреса сервера.
    ///
    /// Адреса перебираются по порядку: у имени их бывает несколько, и первый
    /// может не отвечать — так бывает у сервера с записью IPv6 в сети без
    /// IPv6.
    async fn dial(&self) -> JuicityResult<Arc<Link>> {
        let addresses = connect::resolve(&*self.dialer, &self.host, self.port)
            .await
            .map_err(|e| JuicityError::disconnected(e.to_string()))?;

        let mut last = None;
        for address in addresses {
            match Link::connect(&self.config, &*self.dialer, address, &self.server_name).await {
                Ok(link) => {
                    tracing::debug!(%address, "поднято соединение Juicity");
                    return Ok(link);
                }
                // Неверный пароль на одном адресе будет неверным и на
                // остальных: перебирать дальше нечего.
                Err(err @ JuicityError::AuthRejected) => return Err(err),
                Err(err) => last = Some(err),
            }
        }
        Err(last.unwrap_or_else(|| {
            JuicityError::disconnected("у адреса сервера не оказалось ни одного адреса")
        }))
    }
}

/// Открытый поток вместе с соединением, которое его держит.
///
/// Соединение здесь не для удобства: пока живёт поток, обязан жить эндпойнт,
/// а его владеет [`Link`].
pub struct Stream {
    /// Соединение. Роняется последним.
    pub link: Arc<Link>,
    /// Пишущая половина.
    pub send: quinn::SendStream,
    /// Читающая половина.
    pub recv: quinn::RecvStream,
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream").field("link", &self.link).finish()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use penguin_proto::error::ProtocolError;
    use tokio::net::{TcpStream, UdpSocket};

    use super::*;

    const TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    /// Звонящий, который никуда не звонит.
    #[derive(Debug)]
    struct NoDialer;

    #[async_trait::async_trait]
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

    fn pool(config: JuicityConfig) -> JuicityResult<LinkPool> {
        LinkPool::new(config, Arc::new(NoDialer))
    }

    #[tokio::test]
    async fn a_fresh_pool_holds_no_connections() {
        // Рукопожатие платится тогда, когда в направление пошли, а не когда
        // его включили.
        let pool = pool(config()).expect("собирается");
        assert!(pool.is_empty().await);
    }

    #[tokio::test]
    async fn bad_settings_are_caught_before_any_connection() {
        assert!(
            pool(JuicityConfig {
                password: String::new(),
                ..config()
            })
            .is_err()
        );
    }

    #[tokio::test]
    async fn the_name_for_tls_comes_from_the_settings_and_then_from_the_address() {
        let plain = pool(config()).expect("собирается");
        assert_eq!(plain.server_name, "example.com");

        let mut config = config();
        config.tls.sni = Some("cdn.example.com".to_owned());
        assert_eq!(
            pool(config).expect("собирается").server_name,
            "cdn.example.com"
        );
    }
}
