//! QUIC сервера: сертификат из PEM, ALPN `h3`, датаграммы.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::ServerConfig;

/// ALPN HTTP/3.
const ALPN_H3: &[u8] = b"h3";

/// Сколько молчания терпеть. Клиент шлёт пробу живости раз в десять секунд.
const IDLE: Duration = Duration::from_secs(60);

/// Настройки QUIC по файлам сертификата.
pub fn server_config(config: &ServerConfig) -> Result<quinn::ServerConfig> {
    let certs = load_certs(&config.cert)?;
    let key = load_key(&config.cert_key)?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS 1.3")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("сертификат не сходится со своим ключом")?;
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];

    let crypto = QuicServerConfig::try_from(tls).context("TLS не годится для QUIC")?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(IDLE.try_into().context("срок молчания")?));
    server.transport_config(Arc::new(transport));
    Ok(server)
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).with_context(|| format!("не читается сертификат `{}`", path.display()))?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("сертификат `{}` не разбирается", path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("в `{}` нет сертификатов", path.display());
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path)
        .with_context(|| format!("не читается ключ сертификата `{}`", path.display()))?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .with_context(|| format!("ключ `{}` не разбирается", path.display()))?
        .with_context(|| format!("в `{}` нет закрытого ключа", path.display()))
}
