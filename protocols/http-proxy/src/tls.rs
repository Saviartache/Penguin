//! TLS до прокси: проверка сертификата или явный отказ от неё.
//!
//! Проверяется сертификат **прокси**, а не того сервера, к которому он потом
//! соединяет: с точки зрения TLS прокси и есть собеседник. Дальше внутри
//! тоннеля идёт свой TLS приложения, и его этот слой не видит вовсе.
//!
//! `insecure` снимает единственную защиту от подмены прокси: с ним любой, кто
//! перехватил трафик, становится «прокси» — и читает пароль из заголовка
//! `Proxy-Authorization`. Он остаётся в настройках, потому что без него не
//! отладить свой прокси с самоподписанным сертификатом, — но интерфейс обязан
//! говорить о нём вслух, а журнал предупреждает при каждом подключении.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_platform_verifier::BuilderVerifierExt;

use crate::config::TlsConfig;
use crate::error::{HttpProxyError, HttpProxyResult};

/// Протокол, о котором договариваются в ALPN.
///
/// `CONNECT` — это HTTP/1.1, и объявлять что-то другое незачем: прокси,
/// умеющий HTTP/2, от такого объявления не заработает, а придирчивый к ALPN
/// — сломается.
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Собирает настройки TLS.
pub fn client_config(tls: &TlsConfig) -> HttpProxyResult<rustls::ClientConfig> {
    // Провайдер задаётся явно, а не берётся из глобального умолчания
    // процесса: умолчание может выставить кто угодно из соседних крейтов, и
    // отлаживать такое потом невозможно.
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| HttpProxyError::config(format!("TLS: {e}")))?;

    let mut config = if tls.insecure {
        tracing::warn!(
            "проверка сертификата прокси отключена: подменить его сможет любой, \
             кто видит ваш трафик, — и прочитает пароль из заголовка"
        );
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerification::new(provider)))
            .with_no_client_auth()
    } else {
        builder.with_platform_verifier().with_no_client_auth()
    };

    config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
    Ok(config)
}

/// Полное отсутствие проверки.
#[derive(Debug)]
struct NoVerification {
    provider: Arc<CryptoProvider>,
}

impl NoVerification {
    fn new(provider: Arc<CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_says_http11() {
        let config = client_config(&TlsConfig::default()).expect("собирается");
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn insecure_mode_builds() {
        let tls = TlsConfig {
            insecure: true,
            ..TlsConfig::default()
        };
        client_config(&tls).expect("собирается");
    }
}
