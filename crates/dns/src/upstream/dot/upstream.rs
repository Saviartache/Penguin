//! DNS-over-TLS (RFC 7858): порт 853, перед сообщением его длина двумя байтами.
//!
//! Прячет от провайдера имя VPN-сервера при загрузочном разрешении. TLS и
//! проверка сертификата через хранилище системы те же, что у протоколов.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use penguin_core::address::SocketAddress;
use penguin_proto::dialer::Dialer;
use rustls::pki_types::ServerName;
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::{Sockets, Upstream, socket_error};
use crate::config::UPSTREAM_TIMEOUT;
use crate::error::{DnsError, DnsResult};

/// Порт DNS-over-TLS.
pub const DOT_PORT: u16 = 853;

/// Наибольший ответ.
const MAX_RESPONSE: usize = 65_535;

/// DNS поверх TLS.
pub struct DotUpstream {
    address: String,
    server_name: String,
    connector: TlsConnector,
    sockets: Sockets,
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
        })
    }

    /// Берёт сокеты у набирателя: мимо собственного тоннеля.
    pub fn through(mut self, sockets: Arc<dyn Dialer>) -> Self {
        self.sockets = Some(sockets);
        self
    }
}

#[async_trait]
impl Upstream for DotUpstream {
    fn describe(&self) -> String {
        format!("tls://{}#{}", self.address, self.server_name)
    }

    async fn query(&self, request: &[u8]) -> DnsResult<Vec<u8>> {
        let exchange = async {
            let stream = match &self.sockets {
                Some(sockets) => {
                    let address: SocketAddr = self.address.parse().map_err(|_| {
                        DnsError::Config(format!("адрес DoT `{}` не числовой", self.address))
                    })?;
                    sockets.dial_tcp(address).await.map_err(socket_error)?
                }
                None => TcpStream::connect(&self.address).await?,
            };
            let _ = stream.set_nodelay(true);

            let name = ServerName::try_from(self.server_name.clone()).map_err(|_| {
                DnsError::Config(format!("неверное имя сервера `{}`", self.server_name))
            })?;
            let mut stream = self.connector.connect(name, stream).await?;

            let length = u16::try_from(request.len())
                .map_err(|_| DnsError::Malformed("запрос длиннее 65 535 байт".to_owned()))?;
            stream.write_all(&length.to_be_bytes()).await?;
            stream.write_all(request).await?;
            stream.flush().await?;

            let mut length = [0u8; 2];
            stream.read_exact(&mut length).await?;
            let length = u16::from_be_bytes(length) as usize;
            if length == 0 || length > MAX_RESPONSE {
                return Err(DnsError::Malformed(format!(
                    "нелепая длина ответа: {length}"
                )));
            }

            let mut response = vec![0u8; length];
            stream.read_exact(&mut response).await?;
            Ok::<Vec<u8>, DnsError>(response)
        };

        // Один бюджет на соединение, рукопожатие и обмен.
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
