//! TLS сервера: сертификат из PEM; QUIC с ALPN `h3`, TCP с `h2` и `http/1.1` (прикрытие).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::ServerConfig;

/// ALPN HTTP/3.
const ALPN_H3: &[u8] = b"h3";

/// ALPN HTTP/2.
pub(crate) const ALPN_H2: &[u8] = b"h2";

/// ALPN HTTP/1.1: на нём только сайт.
const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Сколько молчания терпеть. Клиент шлёт пробу живости раз в десять секунд.
const IDLE: Duration = Duration::from_secs(60);

/// TLS 1.3 по файлам сертификата; `alpn` — по предпочтению сервера.
fn tls_config(config: &ServerConfig, alpn: &[&[u8]]) -> Result<rustls::ServerConfig> {
    let certs = load_certs(&config.cert)?;
    let key = load_key(&config.cert_key)?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 1.3")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("сертификат не сходится со своим ключом")?;
    tls.alpn_protocols = alpn.iter().map(|name| name.to_vec()).collect();
    Ok(tls)
}

/// Приём TLS по TCP: HTTP/2, а без него — сайт по HTTP/1.1.
pub fn tcp_acceptor(config: &ServerConfig) -> Result<tokio_rustls::TlsAcceptor> {
    let tls = tls_config(config, &[ALPN_H2, ALPN_HTTP11])?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(tls)))
}

/// Настройки QUIC по файлам сертификата.
pub fn server_config(config: &ServerConfig) -> Result<quinn::ServerConfig> {
    let tls = tls_config(config, &[ALPN_H3])?;
    let crypto = QuicServerConfig::try_from(tls).context("TLS не годится для QUIC")?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(IDLE.try_into().context("срок молчания")?));
    server.transport_config(Arc::new(transport));
    Ok(server)
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .with_context(|| format!("сертификат `{}` не читается", path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("в `{}` нет сертификатов", path.display());
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .with_context(|| format!("ключ `{}` не читается", path.display()))
}
