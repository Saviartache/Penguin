//! TLS: SNI, ALPN, проверка сертификата, закрепление отпечатка, режим без
//! проверки.
//!
//! Пять способов решить, свой ли сервер на том конце, — по убыванию доверия:
//!
//! | Настройка | Как проверяется | Когда уместно |
//! |---|---|---|
//! | ничего | хранилищем сертификатов системы | обычный сервер с настоящим сертификатом |
//! | `ca` | своим корневым сертификатом | своя инфраструктура |
//! | `pin_sha256` | отпечатком листового сертификата | самоподписанный сертификат |
//! | `pin_chain_sha256` | отпечатком всей цепочки | то же, но так считает Juicity |
//! | `insecure` | никак | отладка, и только |
//!
//! `insecure` снимает единственную защиту от подмены сервера: с ним любой,
//! кто перехватил трафик, становится «сервером» — и читает всё, что в него
//! уходит. Он остаётся в настройках, потому что без него не отладить свой
//! сервер, — но интерфейс обязан говорить о нём вслух (`AGENTS.md` §5.3), а
//! журнал предупреждает при каждом подключении.
//!
//! Закрепление отпечатка — разумная середина: цепочка не строится, но сервер
//! обязан предъявить ровно тот сертификат, что назван в настройках.
//!
//! # Почему это здесь
//!
//! Половине протоколов из `plan.md` нужен ровно этот набор полей и ровно эта
//! таблица доверия. Написанная в каждом крейте заново, она означала бы, что
//! `insecure` в одном протоколе выключает проверку целиком, а в другом —
//! только цепочку.

use std::sync::Arc;

use penguin_core::address::Address;
use ring::digest;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
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

/// Настройки TLS, общие для всех протоколов, которые им пользуются.
///
/// Встраивается в конфигурацию протокола через `#[serde(flatten)]` или
/// отдельным полем `tls` — как протоколу привычнее; набор полей от этого не
/// меняется, и одинаковые имена в файле настроек — это тоже часть договора с
/// человеком, который его правит.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Имя, подставляемое в TLS вместо адреса сервера.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,

    /// Список ALPN. Пусто — берётся тот, что протокол считает своим.
    ///
    /// Трогать его почти никогда не нужно, и это тот случай, когда пустое
    /// значение содержательно: у каждого протокола есть ALPN, под который он
    /// маскируется, и подставлять его должен протокол, а не человек.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,

    /// Не проверять сертификат.
    ///
    /// Снимает единственную защиту от подмены сервера. Держится отдельным
    /// полем именно затем, чтобы интерфейс мог сказать об этом вслух.
    #[serde(default)]
    pub insecure: bool,

    /// Отпечаток сертификата SHA-256 в шестнадцатеричной записи.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "pinSHA256")]
    pub pin_sha256: Option<String>,

    /// Отпечаток SHA-256 всей цепочки сертификатов.
    ///
    /// Не то же, что [`TlsConfig::pin_sha256`]: там отпечаток одного листового
    /// сертификата, здесь — свёртка по всей цепочке, какой её прислал сервер.
    /// Считается так: отпечаток первого сертификата, потом для каждого
    /// следующего `SHA-256(предыдущая свёртка + отпечаток следующего)`.
    ///
    /// Способ придуман Juicity, и других его пользователей нет. Поле лежит
    /// здесь, а не у него, потому что таблица доверия в проекте одна: способ,
    /// заведённый в крейте протокола, означал бы, что `insecure` в одном
    /// месте выключает проверку целиком, а в другом — только цепочку.
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
    ///
    /// Зовётся из `validate` протокола: ошибку в поле форма обязана показать
    /// сразу, а не через минуту неудачного подключения.
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

/// Готовый к работе клиент TLS: настройки собраны, имя сервера разобрано.
///
/// Собирается один раз при подъёме направления, а не на каждый поток:
/// разбор PEM и построение хранилища корней стоят заметно дороже самого
/// рукопожатия.
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
    /// Собирает клиента под конкретный сервер.
    ///
    /// `default_alpn` — то, что протокол объявляет, когда в настройках ALPN не
    /// задан. Пустой список означает «не объявлять ALPN вовсе»; так делают
    /// протоколы, которым он не нужен, но пустым его лучше не оставлять:
    /// клиент без ALPN отличается от браузера первым же пакетом.
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

    /// Оборачивает соединение в TLS.
    ///
    /// Срок здесь обязателен: сервер, принявший соединение и замолчавший на
    /// рукопожатии, иначе держал бы поток приложения вечно.
    pub async fn connect<S>(&self, io: S) -> TransportResult<tokio_rustls::client::TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        deadline::handshake("рукопожатие TLS", async {
            // Ошибка сокета переводится сразу: срок обязан говорить на том же
            // языке, что и всё остальное здесь.
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
    // Провайдер задаётся явно, а не берётся из глобального умолчания
    // процесса: умолчание может выставить кто угодно из соседних крейтов, и
    // отлаживать такое потом невозможно.
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
/// Порядок такой: явный `sni`, потом домен сервера, потом его адрес. Последний
/// случай — сервер, заданный числовым адресом без SNI: имени взять неоткуда, и
/// сертификат придётся проверять по адресу. Работает это только с
/// сертификатом, выписанным на адрес, — редкость, — поэтому в журнал уходит
/// предупреждение: иначе ошибка проверки выглядит необъяснимой.
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
/// Двоеточия принимаются, потому что именно так отпечаток выводят `openssl` и
/// браузеры, — а человек его оттуда и копирует. Base64 принимается потому, что
/// в этом виде отпечаток цепочки печатает Juicity, и требовать от человека
/// перевода в другую запись значит требовать сделать это без ошибки.
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
/// Разделители выбрасываются все, включая `-`: в шестнадцатеричной записи его
/// ставят вместо двоеточия. В base64 он значащий, поэтому та разбирается из
/// исходной строки, а не из очищенной.
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
    let mut cursor = std::io::Cursor::new(pem);
    let roots: Result<Vec<_>, _> = rustls_pemfile::certs(&mut cursor).collect();
    let roots = roots
        .map_err(|e| TransportError::config(format!("`{path}` не разбирается как PEM: {e}")))?;

    if roots.is_empty() {
        return Err(TransportError::config(format!(
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
        let actual = digest::digest(&digest::SHA256, end_entity.as_ref());
        // Сравнение обычное, а не постоянного времени: отпечаток — не секрет,
        // он лежит в конфигурации открытым текстом.
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
///
/// От [`PinnedCertificate`] отличается тем, что закрепляет не один сертификат,
/// а весь ряд, который прислал сервер: замена любого промежуточного меняет
/// свёртку. Дороже для того, кто перевыпускает сертификаты, и строже к тому,
/// кто их подменяет.
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

/// Свёртка цепочки: отпечаток первого, дальше отпечаток пары со следующим.
///
/// `None` — цепочка пуста. Считать такую нечем, и принимать её тем более.
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

        // Сравнение обычное, а не постоянного времени: отпечаток — не секрет,
        // он лежит в конфигурации открытым текстом.
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
        // ALPN — часть маскировки: сервер, объявивший не то, виден первым же
        // пакетом рукопожатия. Значит, умолчание задаёт протокол, а не человек.
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
        // Не ошибка: сертификат, выписанный на адрес, бывает. Предупреждение
        // в журнале есть, отказа нет.
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
        // 63 цифры — на одну меньше, чем нужно.
        assert!(parse_fingerprint(&"a".repeat(63)).is_err());
    }

    #[test]
    fn a_fingerprint_in_base64_is_understood_too() {
        // В этой записи отпечаток цепочки печатает Juicity: требовать от
        // человека перевода в другую значит требовать сделать это без ошибки.
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
        // Свёртка начинается с отпечатка первого сертификата: цепочка из
        // одного и лист совпадают, и это не совпадение, а определение.
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
        // Свёртка складывается по порядку: цепочка, переставленная местами, —
        // это другая цепочка, и принять её значит не проверить ничего.
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
        // Проверен будет один, и угадывать какой человеку не с чего.
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
        // `insecure` отменяет проверку целиком, включая отпечаток. Настройка,
        // где стоят оба, обещает защиту, которой нет, — и молчать об этом
        // хуже, чем отказать.
        let tls = TlsConfig {
            insecure: true,
            pin_sha256: Some("ab".repeat(32)),
            ..TlsConfig::default()
        };
        assert!(tls.validate().is_err());
    }

    #[test]
    fn an_empty_sni_is_a_mistake_not_a_default() {
        // Пустая строка в поле означает, что человек его открыл и не заполнил;
        // молча подставить домен значит скрыть это от него.
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
