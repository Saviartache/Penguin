//! DNS-over-TLS.
//!
//! RFC 7858: тот же DNS, но внутри TLS на порту 853, и перед каждым
//! сообщением идёт его длина двумя байтами — соединение потоковое, а границы
//! сообщений нужны.
//!
//! Смысл здесь ровно один: скрыть от провайдера имя, которое спрашивают. Это
//! важно для **загрузочного** разрешения — имени самого VPN-сервера, которое
//! спрашивается до того, как тоннель поднят, и потому идёт открыто.
//!
//! TLS берётся тот же, что у протокола (`rustls` 0.23) и с той же проверкой
//! сертификата через хранилище системы. Второй, отдельный TLS-стек ради DNS
//! означал бы вторую реализацию, которую надо отдельно обновлять при каждой
//! уязвимости.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustls::pki_types::ServerName;
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::Upstream;
use crate::error::{DnsError, DnsResult};

/// Порт DNS-over-TLS.
pub const DOT_PORT: u16 = 853;

/// Сколько ждать ответа.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Наибольший ответ.
const MAX_RESPONSE: usize = 65_535;

/// DNS поверх TLS.
pub struct DotUpstream {
    address: String,
    server_name: String,
    connector: TlsConnector,
}

impl std::fmt::Debug for DotUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DotUpstream")
            .field("address", &self.address)
            .field("server_name", &self.server_name)
            .finish()
    }
}

impl DotUpstream {
    /// Создаёт апстрим.
    ///
    /// `address` — куда соединяться, `server_name` — какое имя проверять в
    /// сертификате. Они различаются намеренно: адрес числовой (разрешать его
    /// негде — мы и есть разрешатель), а имя нужно проверке сертификата.
    pub fn new(address: impl Into<String>, server_name: impl Into<String>) -> DnsResult<Self> {
        let mut address = address.into();
        if !address.contains(':') {
            address = format!("{address}:{DOT_PORT}");
        }

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
        })
    }
}

#[async_trait]
impl Upstream for DotUpstream {
    fn describe(&self) -> String {
        format!("tls://{}#{}", self.address, self.server_name)
    }

    async fn query(&self, request: &[u8]) -> DnsResult<Vec<u8>> {
        let exchange = async {
            let stream = TcpStream::connect(&self.address).await?;
            let _ = stream.set_nodelay(true);

            let name = ServerName::try_from(self.server_name.clone()).map_err(|_| {
                DnsError::Config(format!("неверное имя сервера `{}`", self.server_name))
            })?;
            let mut stream = self.connector.connect(name, stream).await?;

            // Длина перед сообщением: соединение потоковое, и без неё
            // получатель не знает, где кончается один запрос и начинается
            // следующий.
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

        tokio::time::timeout(TIMEOUT, exchange)
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
    fn address_and_name_are_separate() {
        // Адрес числовой — разрешать его негде, мы и есть разрешатель. Имя
        // нужно проверке сертификата.
        let upstream = DotUpstream::new("1.1.1.1", "cloudflare-dns.com").expect("собирается");
        assert_eq!(upstream.describe(), "tls://1.1.1.1:853#cloudflare-dns.com");
    }

    #[tokio::test]
    async fn unreachable_server_times_out() {
        // Подсеть из RFC 5737: туда ничего не идёт.
        let upstream = DotUpstream::new("192.0.2.1", "example.com").expect("собирается");
        let started = std::time::Instant::now();
        assert!(upstream.query(&[0u8; 12]).await.is_err());
        assert!(started.elapsed() < TIMEOUT * 3, "ожидание затянулось");
    }
}
