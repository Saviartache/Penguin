//! TLS: SNI, проверка сертификата, закрепление отпечатка, режим без проверки.
//!
//! Четыре способа решить, свой ли сервер на том конце, — по убыванию доверия:
//!
//! | Настройка | Как проверяется | Когда уместно |
//! |---|---|---|
//! | ничего | хранилищем сертификатов системы | обычный сервер с настоящим сертификатом |
//! | `ca` | своим корневым сертификатом | своя инфраструктура |
//! | `pin_sha256` | отпечатком листового сертификата | самоподписанный сертификат |
//! | `insecure` | никак | отладка, и только |
//!
//! `insecure` снимает единственную защиту от подмены сервера: с ним любой,
//! кто перехватил трафик, становится «сервером». Он остаётся в настройках,
//! потому что без него не отладить свой сервер, — но интерфейс обязан
//! говорить о нём вслух, а журнал предупреждает при каждом подключении.
//!
//! Закрепление отпечатка — разумная середина: цепочка не проверяется, но
//! сервер обязан предъявить ровно тот сертификат, что назван в настройках.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_platform_verifier::BuilderVerifierExt;
use sha2::{Digest, Sha256};

use crate::config::TlsConfig;
use crate::error::{Hysteria2Error, Hysteria2Result};

/// Протокол, о котором договариваются в ALPN.
///
/// Именно `h3`: сервер Hysteria 2 обязан выглядеть обычным сервером HTTP/3, и
/// любое другое значение выдало бы его первым же пакетом рукопожатия.
pub const ALPN_H3: &[u8] = b"h3";

/// Собирает настройки TLS.
pub fn client_config(tls: &TlsConfig) -> Hysteria2Result<rustls::ClientConfig> {
    // Провайдер задаётся явно, а не берётся из глобального умолчания
    // процесса: умолчание может выставить кто угодно из соседних крейтов, и
    // отлаживать такое потом невозможно.
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| Hysteria2Error::config(format!("TLS: {e}")))?;

    let mut config = if tls.insecure {
        tracing::warn!(
            "проверка сертификата отключена: подменить сервер сможет любой, \
             кто видит ваш трафик"
        );
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerification::new(provider)))
            .with_no_client_auth()
    } else if let Some(pin) = &tls.pin_sha256 {
        let expected = parse_fingerprint(pin)?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCertificate::new(expected, provider)))
            .with_no_client_auth()
    } else if let Some(path) = &tls.ca {
        let roots = load_roots(path)?;
        let verifier = rustls_platform_verifier::Verifier::new_with_extra_roots(roots)
            .map_err(|e| Hysteria2Error::config(format!("свой корневой сертификат: {e}")))?
            .with_provider(provider);
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth()
    } else {
        builder.with_platform_verifier().with_no_client_auth()
    };

    config.alpn_protocols = vec![ALPN_H3.to_vec()];
    Ok(config)
}

/// Разбирает отпечаток: `AB:CD:...` или сплошной шестнадцатеричный ряд.
///
/// Двоеточия принимаются, потому что именно так отпечаток выводят `openssl` и
/// браузеры, — а пользователь его оттуда и копирует.
fn parse_fingerprint(raw: &str) -> Hysteria2Result<[u8; 32]> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !matches!(c, ':' | ' ' | '-'))
        .collect();
    if cleaned.len() != 64 {
        return Err(Hysteria2Error::config(format!(
            "отпечаток SHA-256 должен быть из 64 шестнадцатеричных цифр, получено {}",
            cleaned.len()
        )));
    }

    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        let pair = &cleaned[index * 2..index * 2 + 2];
        *byte = u8::from_str_radix(pair, 16).map_err(|_| {
            Hysteria2Error::config(format!("в отпечатке не шестнадцатеричное `{pair}`"))
        })?;
    }
    Ok(out)
}

/// Читает корневые сертификаты из PEM-файла.
fn load_roots(path: &str) -> Hysteria2Result<Vec<CertificateDer<'static>>> {
    let pem = std::fs::read(path).map_err(|e| {
        Hysteria2Error::config(format!("не читается корневой сертификат `{path}`: {e}"))
    })?;
    let mut cursor = std::io::Cursor::new(pem);
    let roots: Result<Vec<_>, _> = rustls_pemfile::certs(&mut cursor).collect();
    let roots = roots
        .map_err(|e| Hysteria2Error::config(format!("`{path}` не разбирается как PEM: {e}")))?;

    if roots.is_empty() {
        return Err(Hysteria2Error::config(format!(
            "в `{path}` нет ни одного сертификата"
        )));
    }
    Ok(roots)
}

/// Проверка отпечатком листового сертификата.
///
/// Цепочка не строится: смысл закрепления как раз в том, что удостоверяющий
/// центр не нужен. Подпись рукопожатия при этом проверяется как обычно —
/// иначе предъявить чужой сертификат смог бы кто угодно, не владея ключом.
#[derive(Debug)]
struct PinnedCertificate {
    expected: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl PinnedCertificate {
    fn new(expected: [u8; 32], provider: Arc<CryptoProvider>) -> Self {
        Self { expected, provider }
    }
}

impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        // Сравнение обычное, а не постоянного времени: отпечаток — не секрет,
        // он лежит в конфигурации открытым текстом.
        if actual == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "отпечаток сертификата не совпал: ожидался {}, получен {}",
                hex(&self.expected),
                hex(&actual)
            )))
        }
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_is_h3() {
        // Любое другое значение выдало бы сервер первым же пакетом.
        let config = client_config(&TlsConfig::default()).expect("собирается");
        assert_eq!(config.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn insecure_mode_builds() {
        let tls = TlsConfig {
            insecure: true,
            ..TlsConfig::default()
        };
        client_config(&tls).expect("собирается");
    }

    #[test]
    fn parses_fingerprint_in_both_notations() {
        let plain = "a".repeat(64);
        let colons: String = plain
            .as_bytes()
            .chunks(2)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(
            parse_fingerprint(&plain).expect("разбирается"),
            parse_fingerprint(&colons).expect("разбирается")
        );
    }

    #[test]
    fn rejects_malformed_fingerprint() {
        assert!(parse_fingerprint("слишком коротко").is_err());
        assert!(parse_fingerprint(&"z".repeat(64)).is_err());
        // 63 цифры — на одну меньше, чем нужно.
        assert!(parse_fingerprint(&"a".repeat(63)).is_err());
    }

    #[test]
    fn pin_mode_builds() {
        let tls = TlsConfig {
            pin_sha256: Some("ab".repeat(32)),
            ..TlsConfig::default()
        };
        client_config(&tls).expect("собирается");
    }

    #[test]
    fn missing_ca_file_is_reported_clearly() {
        let tls = TlsConfig {
            ca: Some("нет-такого-файла.pem".to_owned()),
            ..TlsConfig::default()
        };
        let err = client_config(&tls).expect_err("файла нет");
        assert!(err.to_string().contains("нет-такого-файла.pem"));
    }
}
