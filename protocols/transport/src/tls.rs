//! TLS: SNI, ALPN, проверка сертификата, закрепление отпечатка, режим без проверки.
//!
//! Проверка по убыванию доверия: системное хранилище, `ca`, `pin_sha256`
//! (лист), `pin_chain_sha256` (вся цепочка, как у Juicity), `insecure` (только
//! отладка; интерфейс обязан о нём предупреждать, `AGENTS.md` §5.3).

use std::sync::Arc;

use penguin_core::address::Address;
use ring::digest;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, IpAddr as PkiIpAddr, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_platform_verifier::BuilderVerifierExt;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::deadline;
use crate::error::{TransportError, TransportResult};

/// HTTP/1.1 в ALPN. То, что объявляет обычный `CONNECT`-прокси.
pub const ALPN_HTTP11: &[u8] = b"http/1.1";
/// HTTP/2 в ALPN.
pub const ALPN_H2: &[u8] = b"h2";
/// HTTP/3 в ALPN. Его объявляют Hysteria 2 и остальные поверх QUIC.
pub const ALPN_H3: &[u8] = b"h3";

/// Настройки TLS, общие для протоколов (`#[serde(flatten)]` или поле `tls`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Имя, подставляемое в TLS вместо адреса сервера.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,

    /// Список ALPN. Пусто — ALPN протокола по умолчанию.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,

    /// Не проверять сертификат: снимает защиту от подмены сервера.
    #[serde(default)]
    pub insecure: bool,

    /// Отпечаток сертификата SHA-256 в шестнадцатеричной записи.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "pinSHA256")]
    pub pin_sha256: Option<String>,

    /// Свёртка SHA-256 всей цепочки: отпечаток первого, далее
    /// `SHA-256(свёртка + отпечаток следующего)` (способ Juicity).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "pinned_certchain_sha256"
    )]
    pub pin_chain_sha256: Option<String>,

    /// Путь к своему корневому сертификату.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,
}

impl TlsConfig {
    /// Проверяет то, что видно без сети.
    pub fn validate(&self) -> TransportResult<()> {
        if let Some(pin) = &self.pin_sha256 {
            parse_fingerprint(pin)?;
        }
        if let Some(pin) = &self.pin_chain_sha256 {
            parse_fingerprint(pin)?;
        }
        if let Some(sni) = &self.sni
            && sni.trim().is_empty()
        {
            return Err(TransportError::config(
                "SNI задан пустой строкой: либо имя, либо поля нет вовсе",
            ));
        }
        if self.insecure && (self.pin_sha256.is_some() || self.pin_chain_sha256.is_some()) {
            return Err(TransportError::config(
                "`insecure` и отпечаток вместе: отпечаток при этом не проверяется, \
                 и настройка обещает защиту, которой нет",
            ));
        }
        if self.pin_sha256.is_some() && self.pin_chain_sha256.is_some() {
            return Err(TransportError::config(
                "два отпечатка сразу: проверен будет один, и угадывать какой \
                 человеку не с чего — оставьте тот, что дал сервер",
            ));
        }
        Ok(())
    }
}

/// Готовый клиент TLS; собирается один раз на направление (разбор PEM дорог).
#[derive(Clone)]
pub struct TlsClient {
    connector: tokio_rustls::TlsConnector,
    name: ServerName<'static>,
}

impl std::fmt::Debug for TlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClient")
            .field("name", &self.name)
            .finish()
    }
}

impl TlsClient {
    /// Собирает клиента; `default_alpn` — ALPN, если в настройках не задан.
    pub fn new(tls: &TlsConfig, host: &Address, default_alpn: &[&[u8]]) -> TransportResult<Self> {
        let config = client_config(tls, default_alpn)?;
        Ok(Self {
            connector: tokio_rustls::TlsConnector::from(Arc::new(config)),
            name: server_name(tls, host)?,
        })
    }

    /// Имя, которое уйдёт в SNI.
    pub fn server_name(&self) -> &ServerName<'static> {
        &self.name
    }

    /// Оборачивает соединение в TLS со сроком на рукопожатие.
    pub async fn connect<S>(&self, io: S) -> TransportResult<tokio_rustls::client::TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        deadline::handshake("рукопожатие TLS", async {
            self.connector
                .connect(self.name.clone(), io)
                .await
                .map_err(TransportError::from)
        })
        .await
    }
}

/// Собирает настройки TLS.
pub fn client_config(
    tls: &TlsConfig,
    default_alpn: &[&[u8]],
) -> TransportResult<rustls::ClientConfig> {
    // Явный провайдер, не глобальное умолчание процесса
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::config(format!("TLS: {e}")))?;

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
    } else if let Some(pin) = &tls.pin_chain_sha256 {
        let expected = parse_fingerprint(pin)?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedChain::new(expected, provider)))
            .with_no_client_auth()
    } else if let Some(path) = &tls.ca {
        let roots = load_roots(path)?;
        let verifier = rustls_platform_verifier::Verifier::new_with_extra_roots(roots)
            .map_err(|e| TransportError::config(format!("свой корневой сертификат: {e}")))?
            .with_provider(provider);
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth()
    } else {
        builder.with_platform_verifier().with_no_client_auth()
    };

    config.alpn_protocols = if tls.alpn.is_empty() {
        default_alpn.iter().map(|name| name.to_vec()).collect()
    } else {
        tls.alpn
            .iter()
            .map(|name| name.as_bytes().to_vec())
            .collect()
    };
    Ok(config)
}

/// Имя, которое уйдёт в SNI.
///
/// Порядок: `sni`, домен сервера, адрес (с предупреждением: сертификат на адрес редок).
pub fn server_name(tls: &TlsConfig, host: &Address) -> TransportResult<ServerName<'static>> {
    if let Some(sni) = tls.sni.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        return ServerName::try_from(sni.to_owned())
            .map_err(|e| TransportError::config(format!("SNI `{sni}` не разбирается: {e}")));
    }

    match host {
        Address::Domain(domain) => ServerName::try_from(domain.clone())
            .map_err(|e| TransportError::config(format!("имя `{domain}` не годится для TLS: {e}"))),
        Address::Ip(ip) => {
            if !tls.insecure && tls.pin_sha256.is_none() {
                tracing::warn!(
                    %ip,
                    "сервер задан адресом и SNI не задан: сертификат будет \
                     проверяться по адресу, а таких сертификатов почти не бывает"
                );
            }
            Ok(ServerName::IpAddress(PkiIpAddr::from(*ip)))
        }
    }
}

/// Разбирает отпечаток: `AB:CD:...`, сплошной ряд или base64.
///
/// Hex с двоеточиями (`openssl`, браузеры) или base64 (так печатает Juicity).
fn parse_fingerprint(raw: &str) -> TransportResult<[u8; 32]> {
    if let Some(bytes) = from_hex(raw) {
        return Ok(bytes);
    }

    let decoded =
        penguin_core::base64::decode_exact(raw.trim(), 32, "отпечаток").map_err(|_| {
            TransportError::config(
                "отпечаток SHA-256: нужны 64 шестнадцатеричные цифры или те же 32 байта в base64",
            )
        })?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

/// Отпечаток шестнадцатеричным рядом. `None` — запись не эта.
///
/// Разделители `:`, пробел, `-` отбрасываются; base64 разбирается из исходной строки.
fn from_hex(raw: &str) -> Option<[u8; 32]> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !matches!(c, ':' | ' ' | '-'))
        .collect();
    if cleaned.len() != 64 {
        return None;
    }

    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        let pair = cleaned.get(index * 2..index * 2 + 2)?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

/// Читает корневые сертификаты из PEM-файла.
fn load_roots(path: &str) -> TransportResult<Vec<CertificateDer<'static>>> {
    let pem = std::fs::read(path).map_err(|e| {
        TransportError::config(format!("не читается корневой сертификат `{path}`: {e}"))
    })?;
    let roots: Result<Vec<_>, _> = CertificateDer::pem_slice_iter(&pem).collect();
    let roots = roots
        .map_err(|e| TransportError::config(format!("`{path}` не разбирается как PEM: {e}")))?;

    if roots.is_empty() {
        return Err(TransportError::config(format!(
            "в `{path}` нет ни одного сертификата"
        )));
    }
    Ok(roots)
}

/// Проверка отпечатком листа; цепочка не строится, подпись рукопожатия проверяется.
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
        let actual = digest::digest(&digest::SHA256, end_entity.as_ref());
        if actual.as_ref() == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "отпечаток сертификата не совпал: ожидался {}, получен {}",
                hex(&self.expected),
                hex(actual.as_ref())
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

/// Проверка отпечатком всей цепочки, как её считает Juicity.
#[derive(Debug)]
struct PinnedChain {
    expected: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl PinnedChain {
    fn new(expected: [u8; 32], provider: Arc<CryptoProvider>) -> Self {
        Self { expected, provider }
    }
}

/// Свёртка цепочки; `None` — цепочка пуста.
fn chain_hash<'a>(chain: impl Iterator<Item = &'a [u8]>) -> Option<[u8; 32]> {
    let mut folded: Option<[u8; 32]> = None;
    for cert in chain {
        let one = digest::digest(&digest::SHA256, cert);
        let one: [u8; 32] = one.as_ref().try_into().ok()?;
        folded = Some(match folded {
            None => one,
            Some(previous) => {
                let mut pair = [0u8; 64];
                pair[..32].copy_from_slice(&previous);
                pair[32..].copy_from_slice(&one);
                digest::digest(&digest::SHA256, &pair)
                    .as_ref()
                    .try_into()
                    .ok()?
            }
        });
    }
    folded
}

impl ServerCertVerifier for PinnedChain {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let chain =
            std::iter::once(end_entity.as_ref()).chain(intermediates.iter().map(AsRef::as_ref));
        let actual = chain_hash(chain).ok_or_else(|| {
            rustls::Error::General("сервер не прислал ни одного сертификата".into())
        })?;

        if actual == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "отпечаток цепочки не совпал: ожидался {}, получен {}",
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

/// Шестнадцатеричная запись — только для текста ошибки.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain() -> Address {
        Address::domain("proxy.example.com")
    }

    #[test]
    fn the_protocol_picks_the_alpn_when_the_config_is_silent() {
        let config = client_config(&TlsConfig::default(), &[ALPN_H3]).expect("собирается");
        assert_eq!(config.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn an_explicit_alpn_wins() {
        let tls = TlsConfig {
            alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
            ..TlsConfig::default()
        };
        let config = client_config(&tls, &[ALPN_H3]).expect("собирается");
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn every_trust_mode_builds() {
        for tls in [
            TlsConfig::default(),
            TlsConfig {
                insecure: true,
                ..TlsConfig::default()
            },
            TlsConfig {
                pin_sha256: Some("ab".repeat(32)),
                ..TlsConfig::default()
            },
            TlsConfig {
                pin_chain_sha256: Some("cd".repeat(32)),
                ..TlsConfig::default()
            },
        ] {
            client_config(&tls, &[ALPN_HTTP11]).expect("собирается");
        }
    }

    #[test]
    fn sni_replaces_the_server_name() {
        let tls = TlsConfig {
            sni: Some("www.microsoft.com".to_owned()),
            ..TlsConfig::default()
        };
        let name = server_name(&tls, &domain()).expect("разбирается");
        assert_eq!(name, ServerName::try_from("www.microsoft.com").unwrap());
    }

    #[test]
    fn without_sni_the_server_domain_is_used() {
        let name = server_name(&TlsConfig::default(), &domain()).expect("разбирается");
        assert_eq!(name, ServerName::try_from("proxy.example.com").unwrap());
    }

    #[test]
    fn a_numeric_server_without_sni_still_works() {
        let host = Address::Ip("203.0.113.5".parse().unwrap());
        let name = server_name(&TlsConfig::default(), &host).expect("разбирается");
        assert!(matches!(name, ServerName::IpAddress(_)));
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
        assert!(parse_fingerprint(&"a".repeat(63)).is_err());
    }

    #[test]
    fn a_fingerprint_in_base64_is_understood_too() {
        let bytes = [0x9a_u8; 32];
        let hex_form = "9a".repeat(32);
        for encoded in [
            penguin_core::base64::encode(&bytes),
            penguin_core::base64::encode_url(&bytes),
        ] {
            assert_eq!(
                parse_fingerprint(&encoded).expect("разбирается"),
                parse_fingerprint(&hex_form).expect("разбирается"),
                "{encoded}"
            );
        }
    }

    #[test]
    fn a_chain_of_one_hashes_like_a_single_certificate() {
        let cert = b"cert";
        let folded = chain_hash(std::iter::once(cert.as_slice())).expect("считается");
        let plain: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, cert)
            .as_ref()
            .try_into()
            .expect("32 байта");
        assert_eq!(folded, plain);
    }

    #[test]
    fn the_order_of_the_chain_is_part_of_the_fingerprint() {
        let first = b"one".as_slice();
        let second = b"two".as_slice();
        let straight = chain_hash([first, second].into_iter()).expect("считается");
        let reversed = chain_hash([second, first].into_iter()).expect("считается");
        assert_ne!(straight, reversed);
        assert_ne!(
            straight,
            chain_hash(std::iter::once(first)).expect("считается")
        );
    }

    #[test]
    fn an_empty_chain_has_no_fingerprint() {
        assert!(chain_hash(std::iter::empty()).is_none());
    }

    #[test]
    fn two_fingerprints_at_once_are_refused() {
        let tls = TlsConfig {
            pin_sha256: Some("ab".repeat(32)),
            pin_chain_sha256: Some("cd".repeat(32)),
            ..TlsConfig::default()
        };
        assert!(tls.validate().is_err());
    }

    #[test]
    fn missing_ca_file_is_reported_clearly() {
        let tls = TlsConfig {
            ca: Some("нет-такого-файла.pem".to_owned()),
            ..TlsConfig::default()
        };
        let err = client_config(&tls, &[ALPN_HTTP11]).expect_err("файла нет");
        assert!(err.to_string().contains("нет-такого-файла.pem"));
    }

    #[test]
    fn a_promise_of_safety_that_is_not_kept_is_refused() {
        let tls = TlsConfig {
            insecure: true,
            pin_sha256: Some("ab".repeat(32)),
            ..TlsConfig::default()
        };
        assert!(tls.validate().is_err());
    }

    #[test]
    fn an_empty_sni_is_a_mistake_not_a_default() {
        let tls = TlsConfig {
            sni: Some("   ".to_owned()),
            ..TlsConfig::default()
        };
        assert!(tls.validate().is_err());
    }

    #[test]
    fn validation_happens_before_the_network() {
        let tls = TlsConfig {
            pin_sha256: Some("не отпечаток".to_owned()),
            ..TlsConfig::default()
        };
        assert!(tls.validate().is_err());
        TlsConfig::default().validate().expect("настройки верны");
    }
}
