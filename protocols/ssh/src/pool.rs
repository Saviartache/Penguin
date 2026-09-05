//! Соединение SSH одного направления: поднимается один раз и переиспользуется.
//!
//! У `direct-tcpip` нет предела одновременных каналов, который заставил бы
//! заводить второе соединение, — в отличие от QUIC у Juicity
//! (`protocols/juicity/src/pool.rs`). Ровно так работает и `ssh -D`: одно
//! соединение на весь профиль, а не одно на вкладку браузера. Поэтому здесь
//! держится не список, а единственное соединение, которое поднимается
//! заново, если умерло.

use std::sync::Arc;

use penguin_core::address::{Address, SocketAddress};
use penguin_proto::dialer::Dialer;
use tokio::sync::Mutex;

use crate::config::SshConfig;
use crate::error::SshResult;
use crate::session::Link;
use crate::stream::SshStream;

/// Соединение SSH направления.
pub struct SshPool {
    config: SshConfig,
    dialer: Arc<dyn Dialer>,
    /// Хост сервера, разобранный один раз при сборке.
    host: Address,
    /// Порт сервера.
    port: u16,
    link: Mutex<Option<Arc<Link>>>,
}

impl std::fmt::Debug for SshPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshPool")
            .field("host", &self.host)
            .field("port", &self.port)
            .finish()
    }
}

impl SshPool {
    /// Заводит направление. Соединения при этом не открывается.
    pub fn new(config: SshConfig, dialer: Arc<dyn Dialer>) -> SshResult<Self> {
        config.validate()?;
        let (host, port) = config.endpoint()?;
        Ok(Self {
            config,
            dialer,
            host,
            port,
            link: Mutex::new(None),
        })
    }

    /// Настройки направления.
    pub fn config(&self) -> &SshConfig {
        &self.config
    }

    /// Открывает канал `direct-tcpip` до цели.
    ///
    /// Соединение могло умереть, пока лежало без дела: сервер закрывает их по
    /// своему сроку, и узнаём мы об этом только при попытке. Поэтому неудача
    /// — повод поднять его заново, а не сразу показывать человеку ошибку.
    pub async fn open(&self, target: &SocketAddress) -> SshResult<SshStream> {
        let link = self.take_or_create().await?;
        match link.open_channel(target).await {
            Ok(channel) => Ok(SshStream::new(link, channel)),
            Err(err) => {
                tracing::debug!(%err, "соединение SSH не годится");
                self.forget().await;

                let link = self.take_or_create().await?;
                let channel = link.open_channel(target).await?;
                Ok(SshStream::new(link, channel))
            }
        }
    }

    /// Есть ли живое соединение. Нужно журналу и тестам.
    pub async fn is_empty(&self) -> bool {
        self.link.lock().await.is_none()
    }

    /// Закрывает соединение направления.
    pub async fn close_all(&self) {
        if let Some(link) = self.link.lock().await.take() {
            link.close().await;
        }
    }

    /// Берёт годное соединение или поднимает новое.
    async fn take_or_create(&self) -> SshResult<Arc<Link>> {
        let mut guard = self.link.lock().await;

        if let Some(link) = guard.as_ref()
            && link.usable()
        {
            return Ok(Arc::clone(link));
        }

        let link = Link::connect(&self.config, &self.host, self.port, &*self.dialer).await?;
        *guard = Some(Arc::clone(&link));
        tracing::debug!(host = %self.host, port = self.port, "поднято соединение SSH");
        Ok(link)
    }

    /// Убирает соединение из направления.
    async fn forget(&self) {
        self.link.lock().await.take();
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use penguin_proto::error::ProtocolError;
    use tokio::net::{TcpStream, UdpSocket};

    use super::*;

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

    fn pool(config: SshConfig) -> SshResult<SshPool> {
        SshPool::new(config, Arc::new(NoDialer))
    }

    #[tokio::test]
    async fn a_fresh_pool_holds_no_connection() {
        // Рукопожатие платится тогда, когда в направление пошли, а не когда
        // его включили.
        let pool = pool(config()).expect("собирается");
        assert!(pool.is_empty().await);
    }

    #[tokio::test]
    async fn bad_settings_are_caught_before_any_connection() {
        assert!(
            pool(SshConfig {
                host_fingerprint: String::new(),
                ..config()
            })
            .is_err()
        );
    }

    #[tokio::test]
    async fn closing_an_empty_pool_does_nothing_bad() {
        let pool = pool(config()).expect("собирается");
        pool.close_all().await;
        assert!(pool.is_empty().await);
    }
}
