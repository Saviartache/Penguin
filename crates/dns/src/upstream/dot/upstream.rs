//! Апстрим DoT: адрес, имя в сертификате и живой сеанс.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use penguin_core::address::SocketAddress;
use penguin_proto::dialer::Dialer;
use rustls::pki_types::ServerName;
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::session::{self, Query, Session};
use crate::config::UPSTREAM_TIMEOUT;
use crate::error::{DnsError, DnsResult};
use crate::upstream::{Sockets, Upstream, socket_error};

/// Порт DNS-over-TLS.
pub const DOT_PORT: u16 = 853;

/// Срок на соединение и TLS: внутри тоннеля к ним добавляется рукопожатие с сервером VPN.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// DNS поверх TLS.
pub struct DotUpstream {
    address: String,
    server_name: String,
    connector: TlsConnector,
    sockets: Sockets,
    session: Mutex<Option<Session>>,
}

impl std::fmt::Debug for DotUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DotUpstream")
            .field("address", &self.address)
            .field("server_name", &self.server_name)
            .field("protected", &self.sockets.is_some())
            .finish()
    }
}

impl DotUpstream {
    /// Создаёт апстрим: `address` числовой (разрешать его некому), `server_name` проверяется в сертификате.
    pub fn new(address: impl Into<String>, server_name: impl Into<String>) -> DnsResult<Self> {
        let address: String = address.into();
        let address = SocketAddress::parse_or_port(address.trim(), DOT_PORT)
            .map_err(|e| DnsError::Config(format!("адрес DoT `{address}`: {e}")))?
            .to_wire();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| DnsError::Config(format!("TLS для DNS: {e}")))?
            .with_platform_verifier()
            .with_no_client_auth();

        Ok(Self {
            address,
            server_name: server_name.into(),
            connector: TlsConnector::from(Arc::new(config)),
            sockets: None,
            session: Mutex::new(None),
        })
    }

    /// Берёт сокеты у набирателя: мимо собственного тоннеля.
    pub fn through(mut self, sockets: Arc<dyn Dialer>) -> Self {
        self.sockets = Some(sockets);
        self
    }

    /// Живой сеанс или новый: один на апстрим, сколько бы запросов ни шло.
    fn session(&self) -> Session {
        let mut current = self.session.lock();
        if let Some(session) = current.as_ref().filter(|session| !session.is_closed()) {
            return session.clone();
        }
        let connect = connect(
            self.address.clone(),
            self.server_name.clone(),
            self.connector.clone(),
            self.sockets.clone(),
        );
        let session = session::spawn(async move {
            tokio::time::timeout(CONNECT_TIMEOUT, connect)
                .await
                .map_err(|_| DnsError::Upstream("соединение DoT не поднялось".to_owned()))?
        });
        *current = Some(session.clone());
        session
    }
}

async fn connect(
    address: String,
    server_name: String,
    connector: TlsConnector,
    sockets: Sockets,
) -> DnsResult<TlsStream<TcpStream>> {
    let stream = match &sockets {
        Some(sockets) => {
            let parsed: SocketAddr = address
                .parse()
                .map_err(|_| DnsError::Config(format!("адрес DoT `{address}` не числовой")))?;
            sockets.dial_tcp(parsed).await.map_err(socket_error)?
        }
        None => TcpStream::connect(&address).await?,
    };
    let _ = stream.set_nodelay(true);

    let name = ServerName::try_from(server_name.clone())
        .map_err(|_| DnsError::Config(format!("неверное имя сервера `{server_name}`")))?;
    Ok(connector.connect(name, stream).await?)
}

#[async_trait]
impl Upstream for DotUpstream {
    fn describe(&self) -> String {
        format!("tls://{}#{}", self.address, self.server_name)
    }

    async fn query(&self, request: &[u8]) -> DnsResult<Vec<u8>> {
        let session = self.session();
        let exchange = async {
            let (reply, answer) = tokio::sync::oneshot::channel();
            let query = Query {
                message: request.to_vec(),
                reply,
            };
            let closed = || DnsError::Upstream("сеанс DoT закрыт".to_owned());
            session.send(query).await.map_err(|_| closed())?;
            answer.await.map_err(|_| closed())
        };

        tokio::time::timeout(UPSTREAM_TIMEOUT, exchange)
            .await
            .map_err(|_| DnsError::Upstream(format!("{} не ответил", self.address)))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_the_default_port() {
        let upstream = DotUpstream::new("1.1.1.1", "cloudflare-dns.com").expect("собирается");
        assert!(upstream.address.ends_with(":853"));
    }

    #[test]
    fn keeps_an_explicit_port() {
        let upstream = DotUpstream::new("1.1.1.1:8853", "cloudflare-dns.com").expect("собирается");
        assert!(upstream.address.ends_with(":8853"));
    }

    #[test]
    fn ipv6_is_bracketed_before_the_port() {
        for (raw, wire) in [
            ("2606:4700:4700::1111", "tls://[2606:4700:4700::1111]:853#"),
            (
                "[2606:4700:4700::1111]",
                "tls://[2606:4700:4700::1111]:853#",
            ),
            (
                "[2606:4700:4700::1111]:8853",
                "tls://[2606:4700:4700::1111]:8853#",
            ),
        ] {
            let upstream = DotUpstream::new(raw, "").expect("собирается");
            assert_eq!(upstream.describe(), wire);
        }
    }

    #[test]
    fn a_zone_is_refused() {
        assert!(DotUpstream::new("fe80::1%en0", "example.com").is_err());
    }

    #[test]
    fn address_and_name_are_separate() {
        let upstream = DotUpstream::new("1.1.1.1", "cloudflare-dns.com").expect("собирается");
        assert_eq!(upstream.describe(), "tls://1.1.1.1:853#cloudflare-dns.com");
    }

    #[tokio::test]
    async fn unreachable_server_times_out() {
        let upstream = DotUpstream::new("192.0.2.1", "example.com").expect("собирается");
        let started = std::time::Instant::now();
        assert!(upstream.query(&[0u8; 12]).await.is_err());
        assert!(
            started.elapsed() < UPSTREAM_TIMEOUT * 3,
            "ожидание затянулось"
        );
    }
}
