//! Ведёт рукопожатие Reality: [`verify`] — только до места, где сервер можно
//! проверить, [`connect`] — до конца, до прикладных ключей TLS 1.3.
//!
//! ```text
//! клиент                                              сервер
//!   │                                                     │
//!   │  ClientHello (SessionID = зашифрованные            │
//!   │  данные опознания, auth.rs)          ─────────────>│
//!   │                                                     │
//!   │<───────────────────────────  ServerHello (открыто) │
//!   │                                                     │
//!   │  секрет рукопожатия (key_schedule.rs) из общего    │
//!   │  секрета (EC)DHE настоящего TLS 1.3 — НЕ AuthKey   │
//!   │  Reality; отсюда же — ключ клиента для Finished    │
//!   │                                                     │
//!   │<─ EncryptedExtensions, Certificate, CertificateVerify, Finished ─│
//!   │       (зашифровано, record.rs расшифровывает по мере поступления)
//!   │                                                     │
//!   │  certificate.rs: ключ Ed25519 + подпись            │
//!   │  auth.rs: HMAC-SHA512(AuthKey, ключ) == подпись?   │
//!   │                                                     │
//!  [verify возвращает Verified здесь]           NotRecognized
//!   │                                                     │
//!   │  Finished сервера сверяется с посчитанным          │
//!   │  (key_schedule::verify_finished)                   │
//!   │                                                     │
//!   │  ChangeCipherSpec (мидлбокс-совместимость,         │
//!   │  RFC 8446 Приложение D.4) ─────────────────────────>│
//!   │  свой Finished (зашифрован)           ─────────────>│
//!   │                                                     │
//!   │  Master Secret → прикладные ключи (RFC 8446 §7.1)  │
//!   │                                                     │
//!  RealityStream (application.rs) — байты VLESS дальше
//! ```
//!
//! **Ловушка** (см. `mod.rs`): прикладные секреты трафика выводятся из
//! `Master Secret` с транскриптом ДО `Finished` клиента, но ПОСЛЕ `Finished`
//! сервера (RFC 8446 §7.1) — перепутать эти две границы значит вывести
//! секрет, которым сервер ничего не расшифрует.
//!
//! `CertificateVerify` разбирается только для того, чтобы правильно продвинуть
//! транскрипт, — её подпись не проверяется отдельно. Это не пропуск, но и не
//! то свойство, которое даёт `Finished`: ключ MAC у `Finished` выводится из
//! общего секрета (EC)DHE, а его знает и посредник, ведущий своё рукопожатие
//! с клиентом, — «транскрипт совпал» доказывает целостность канала, а не
//! личность того, кто на другом конце. В обычном TLS 1.3 личность связывает с
//! рукопожатием ровно `CertificateVerify`, и пропускать её там нельзя.
//!
//! Здесь её заменяет HMAC из `auth.rs`, и заменяет полноценно:
//! `AuthKey = HKDF(salt = client_random[..20], ikm = X25519(наш закрытый ключ
//! `key_share`, публичный ключ Reality сервера), info = "REALITY")` —
//! то есть привязан и к нашему `random`, и к нашему `key_share` именно этого
//! рукопожатия. Посредник не может ни вычислить `AuthKey` (не знает ни нашего
//! закрытого ключа, ни ключа Reality сервера), ни выпросить готовый `HMAC` у
//! настоящего сервера: тот отдаёт сертификат уже зашифрованным на общем
//! секрете с **нашим** `key_share`, а подменив `key_share` в `ServerHello`,
//! посредник тем самым лишает себя этого ответа. Подписи `CertificateVerify`
//! это не отменяет как механизм TLS — просто здесь она доказывала бы лишь,
//! что сторона знает закрытый ключ своего же самоподписанного сертификата,
//! что не отличает Reality от обычного сайта, за который сервер себя выдаёт.
//! Разбор RSA и ECDSA поверх уже разобранного X.509 — код без своего
//! свойства.
//!
//! `KeyUpdate` и переиспользование билета (`NewSessionTicket`) не
//! поддержаны — подробности в `application.rs`, где это уже видно на кадрах,
//! приходящих после рукопожатия.
//!
//! `HelloRetryRequest` не поддержан: настоящий сервер Reality всегда отвечает
//! `X25519` сразу, потому что клиент всегда предлагает эту группу первой
//! (`penguin_utls::fingerprint::*`), а конфигурация `xray-core`/`sing-box` не
//! принимает для Reality никакой другой. `ServerHello` с `random`, равным
//! константе `HelloRetryRequest` (RFC 8446 §4.1.3), отвергается как
//! `Malformed`, а не как `NotRecognized`, — второе означало бы, что мы
//! успешно проверили сервер и он нам отказал, а первое честнее: мы просто не
//! умеем вести рукопожатие дальше в этом случае.

use penguin_core::address::Address;
use penguin_utls::ServerHello;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::reality::application::RealityStream;
use crate::reality::cipher_suite::CipherSuite;
use crate::reality::config::RealityConfig;
use crate::reality::error::RealityError;
use crate::reality::record::{
    CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE,
    RecordKey,
};
use crate::reality::{auth, certificate, key_schedule};

/// Код группы `X25519` в `key_share` — RFC 8446 §4.2.7 (`NamedGroup`,
/// значение `0x001D` = 29).
const GROUP_X25519: u16 = 29;

/// `SHA-256("HelloRetryRequest")` — RFC 8446 §4.1.3: `ServerHello.random`
/// равен этой строке ровно тогда, когда сообщение на самом деле
/// `HelloRetryRequest`, а не обычный `ServerHello`. Посчитано и сверено
/// независимо (`openssl dgst -sha256`), а не переписано из чужого исходника.
const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Handshake-типы, которые интересуют этот шаг, — RFC 8446 §B.3.
const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 8;
const HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;
const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 15;
const HANDSHAKE_TYPE_FINISHED: u8 = 20;

/// Сервер подтвердил себя как Reality.
///
/// Значение — просто отметка: проверить его нечем, кроме факта, что функция
/// вернула `Ok`. Соединение при этом не готово к передаче байт VLESS — см.
/// документ модуля.
#[derive(Debug, Clone, Copy)]
pub struct Verified;

/// Ведёт рукопожатие Reality на уже открытом соединении и проверяет
/// сертификат сервера.
pub async fn verify<S>(io: &mut S, config: &RealityConfig) -> Result<Verified, RealityError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let public_key = config.public_key_bytes()?;
    let short_id = config.short_id_bytes()?;
    let server_name = Address::domain(config.server_name.trim());

    let (mut hello, keys) = config
        .fingerprint
        .build(&server_name, [0; 32])
        .map_err(|e| RealityError::Config(e.to_string()))?;
    // Все три отпечатка (`penguin_utls::fingerprint::{chrome,firefox,safari}`)
    // предлагают X25519 первым ключом `key_share` — Reality другой группы не
    // понимает, и звать `x25519_diffie_hellman` дальше есть смысл только для
    // первого ключа.
    let x25519 = keys.first().ok_or_else(|| {
        RealityError::Config("отпечаток не запросил ни одного ключа key_share".to_owned())
    })?;

    let unix_time = current_unix_time();
    let reality_shared_secret =
        x25519
            .x25519_diffie_hellman(&public_key)
            .ok_or(RealityError::Config(
                "первый ключ ClientHello — не X25519".to_owned(),
            ))?;
    let auth_key = auth::derive_auth_key(&reality_shared_secret, &hello.random)?;
    let sealed = auth::seal_session_id(
        &auth_key,
        &hello.random,
        short_id,
        unix_time,
        hello.handshake_bytes(),
    )?;
    hello.patch_session_id(sealed);

    io.write_all(&hello.record_bytes()).await?;
    io.flush().await?;

    let (server_hello, server_hello_message) = read_server_hello(io).await?;
    if server_hello.random == HELLO_RETRY_REQUEST_RANDOM {
        return Err(RealityError::Malformed(
            "сервер запросил HelloRetryRequest — это не поддержано".to_owned(),
        ));
    }
    if server_hello.supported_version != Some(0x0304) {
        return Err(RealityError::UnsupportedNegotiation(format!(
            "supported_version = {:?} вместо TLS 1.3",
            server_hello.supported_version
        )));
    }
    let cipher = CipherSuite::from_u16(server_hello.cipher_suite).ok_or_else(|| {
        RealityError::UnsupportedNegotiation(format!(
            "шифр {:#06x} — не TLS 1.3",
            server_hello.cipher_suite
        ))
    })?;
    let server_key_share = server_hello
        .key_share
        .as_ref()
        .ok_or(RealityError::Malformed(
            "ServerHello без key_share".to_owned(),
        ))?;
    if server_key_share.group != GROUP_X25519 {
        return Err(RealityError::UnexpectedGroup(server_key_share.group));
    }
    let server_public: [u8; 32] = server_key_share
        .data
        .as_slice()
        .try_into()
        .map_err(|_| RealityError::Malformed("key_share сервера — не 32 байта".to_owned()))?;

    let tls_shared_secret =
        x25519
            .x25519_diffie_hellman(&server_public)
            .ok_or(RealityError::Config(
                "первый ключ ClientHello — не X25519".to_owned(),
            ))?;
    let transcript =
        key_schedule::transcript_hash(cipher, &[hello.handshake_bytes(), &server_hello_message]);
    let handshake_keys =
        key_schedule::server_handshake_traffic_keys(cipher, &tls_shared_secret, &transcript)?;
    let mut record_key = RecordKey::new(cipher, &handshake_keys.key, handshake_keys.iv)?;

    read_certificate_and_verify(io, &mut record_key, &auth_key).await
}

/// Ведёт рукопожатие Reality до конца: то же самое, что и [`verify`] (свой
/// `ClientHello`, проверка сертификата сервера через `auth::verify_certificate`),
/// а затем — `CertificateVerify`, `Finished` сервера, свой `Finished` и
/// прикладные ключи TLS 1.3 (RFC 8446 §7.1). Возвращает поток, поверх
/// которого `connector.rs` дальше отправляет байты VLESS.
///
/// Берёт `io` по значению (не `&mut`, как [`verify`]): в отличие от
/// предварительной проверки, соединение здесь не отбрасывается после
/// рукопожатия, а становится [`RealityStream`].
pub async fn connect<S>(mut io: S, config: &RealityConfig) -> Result<RealityStream<S>, RealityError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let public_key = config.public_key_bytes()?;
    let short_id = config.short_id_bytes()?;
    let server_name = Address::domain(config.server_name.trim());

    let (mut hello, keys) = config
        .fingerprint
        .build(&server_name, [0; 32])
        .map_err(|e| RealityError::Config(e.to_string()))?;
    let x25519 = keys.first().ok_or_else(|| {
        RealityError::Config("отпечаток не запросил ни одного ключа key_share".to_owned())
    })?;

    let unix_time = current_unix_time();
    let reality_shared_secret =
        x25519
            .x25519_diffie_hellman(&public_key)
            .ok_or(RealityError::Config(
                "первый ключ ClientHello — не X25519".to_owned(),
            ))?;
    let auth_key = auth::derive_auth_key(&reality_shared_secret, &hello.random)?;
    let sealed = auth::seal_session_id(
        &auth_key,
        &hello.random,
        short_id,
        unix_time,
        hello.handshake_bytes(),
    )?;
    hello.patch_session_id(sealed);

    io.write_all(&hello.record_bytes()).await?;
    io.flush().await?;

    let (server_hello, server_hello_message) = read_server_hello(&mut io).await?;
    if server_hello.random == HELLO_RETRY_REQUEST_RANDOM {
        return Err(RealityError::Malformed(
            "сервер запросил HelloRetryRequest — это не поддержано".to_owned(),
        ));
    }
    if server_hello.supported_version != Some(0x0304) {
        return Err(RealityError::UnsupportedNegotiation(format!(
            "supported_version = {:?} вместо TLS 1.3",
            server_hello.supported_version
        )));
    }
    let cipher = CipherSuite::from_u16(server_hello.cipher_suite).ok_or_else(|| {
        RealityError::UnsupportedNegotiation(format!(
            "шифр {:#06x} — не TLS 1.3",
            server_hello.cipher_suite
        ))
    })?;
    let server_key_share = server_hello
        .key_share
        .as_ref()
        .ok_or(RealityError::Malformed(
            "ServerHello без key_share".to_owned(),
        ))?;
    if server_key_share.group != GROUP_X25519 {
        return Err(RealityError::UnexpectedGroup(server_key_share.group));
    }
    let server_public: [u8; 32] = server_key_share
        .data
        .as_slice()
        .try_into()
        .map_err(|_| RealityError::Malformed("key_share сервера — не 32 байта".to_owned()))?;

    let tls_shared_secret =
        x25519
            .x25519_diffie_hellman(&server_public)
            .ok_or(RealityError::Config(
                "первый ключ ClientHello — не X25519".to_owned(),
            ))?;

    let client_hello_bytes = hello.handshake_bytes();
    let transcript_ch_sh =
        key_schedule::transcript_hash(cipher, &[client_hello_bytes, &server_hello_message]);

    let handshake_secret = key_schedule::handshake_secret(cipher, &tls_shared_secret)?;
    let client_hs_traffic_secret =
        handshake_secret.traffic_secret("c hs traffic", &transcript_ch_sh)?;
    let server_hs_traffic_secret =
        handshake_secret.traffic_secret("s hs traffic", &transcript_ch_sh)?;
    let server_hs_keys = key_schedule::traffic_keys(cipher, &server_hs_traffic_secret)?;
    let client_hs_keys = key_schedule::traffic_keys(cipher, &client_hs_traffic_secret)?;
    let mut read_key = RecordKey::new(cipher, &server_hs_keys.key, server_hs_keys.iv)?;
    let mut write_key = RecordKey::new(cipher, &client_hs_keys.key, client_hs_keys.iv)?;

    let flight = read_server_flight(&mut io, &mut read_key, &auth_key).await?;

    let transcript_before_server_finished = key_schedule::transcript_hash(
        cipher,
        &[
            client_hello_bytes,
            &server_hello_message,
            &flight.messages_before_finished,
        ],
    );
    let server_finished_key = key_schedule::finished_key(cipher, &server_hs_traffic_secret)?;
    if !key_schedule::verify_finished(
        cipher,
        &server_finished_key,
        &transcript_before_server_finished,
        &flight.verify_data,
    ) {
        return Err(RealityError::FinishedMismatch);
    }

    // RFC 8446 §7.1: транскрипт "ClientHello...server Finished" — ДО
    // Finished клиента, но ПОСЛЕ Finished сервера (см. документ модуля).
    // Тот же транскрипт нужен и клиентскому Finished, и прикладным ключам.
    let transcript_through_server_finished = key_schedule::transcript_hash(
        cipher,
        &[
            client_hello_bytes,
            &server_hello_message,
            &flight.messages_before_finished,
            &flight.server_finished_message,
        ],
    );

    let client_finished_key = key_schedule::finished_key(cipher, &client_hs_traffic_secret)?;
    let client_verify_data = key_schedule::finished_verify_data(
        cipher,
        &client_finished_key,
        &transcript_through_server_finished,
    );
    let mut client_finished_message = vec![HANDSHAKE_TYPE_FINISHED];
    client_finished_message
        .extend_from_slice(&(client_verify_data.len() as u32).to_be_bytes()[1..]);
    client_finished_message.extend_from_slice(&client_verify_data);

    // ChangeCipherSpec — совместимость с мидлбоксами (RFC 8446 Приложение
    // D.4): наш SessionID не пуст (Reality кладёт туда данные опознания),
    // а значит настоящий клиент в этом режиме тоже её посылает.
    io.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]).await?;
    let finished_record = write_key.seal(CONTENT_TYPE_HANDSHAKE, &client_finished_message)?;
    io.write_all(&finished_record).await?;
    io.flush().await?;

    let master_secret = handshake_secret.master_secret()?;
    let client_ap_secret =
        master_secret.traffic_secret("c ap traffic", &transcript_through_server_finished)?;
    let server_ap_secret =
        master_secret.traffic_secret("s ap traffic", &transcript_through_server_finished)?;
    let client_ap_keys = key_schedule::traffic_keys(cipher, &client_ap_secret)?;
    let server_ap_keys = key_schedule::traffic_keys(cipher, &server_ap_secret)?;

    let application_read_key = RecordKey::new(cipher, &server_ap_keys.key, server_ap_keys.iv)?;
    let application_write_key = RecordKey::new(cipher, &client_ap_keys.key, client_ap_keys.iv)?;

    Ok(RealityStream::new(
        io,
        application_read_key,
        application_write_key,
    ))
}

/// Три сообщения второй половины серверного полёта: всё, что накопилось до
/// `Finished` (`EncryptedExtensions`, `Certificate`, `CertificateVerify`, в
/// исходных байтах — для транскрипта), и сам `Finished` (тоже в исходных
/// байтах, и отдельно — его `verify_data`).
#[derive(Debug)]
struct ServerFlight {
    /// `EncryptedExtensions` + `Certificate` + `CertificateVerify`, байты
    /// сообщений как пришли (заголовок и тело каждого), без `Finished`.
    messages_before_finished: Vec<u8>,
    /// `Finished` целиком (заголовок и тело) — последний кусок транскрипта
    /// перед `Finished` клиента и прикладными ключами.
    server_finished_message: Vec<u8>,
    /// `verify_data` из тела `Finished` — то, что сверяется с посчитанным
    /// ([`key_schedule::verify_finished`]).
    verify_data: Vec<u8>,
}

/// Читает `EncryptedExtensions`, `Certificate` (проверяя его тем же HMAC,
/// что и [`verify`]), `CertificateVerify` (не проверяя подпись — см.
/// документ модуля) и останавливается на `Finished` сервера, не проверяя
/// его — это делает вызывающий ([`connect`]), которому для этого нужен ещё
/// и транскрипт без `Finished`.
async fn read_server_flight<S>(
    io: &mut S,
    record_key: &mut RecordKey,
    auth_key: &[u8; 32],
) -> Result<ServerFlight, RealityError>
where
    S: AsyncRead + Unpin,
{
    let mut handshake_buffer = Vec::new();
    let mut messages_before_finished = Vec::new();
    let mut seen_encrypted_extensions = false;
    let mut seen_certificate = false;

    loop {
        let (header, mut body) = read_record(io).await?;
        match header[0] {
            CONTENT_TYPE_CHANGE_CIPHER_SPEC => continue,
            CONTENT_TYPE_APPLICATION_DATA => {}
            other => {
                return Err(RealityError::Malformed(format!(
                    "тип записи {other:#04x} вместо application_data (0x17) или \
                     change_cipher_spec (0x14)"
                )));
            }
        }

        let (inner_type, plaintext) = record_key.open(&header, &mut body)?;
        if inner_type != CONTENT_TYPE_HANDSHAKE {
            return Err(RealityError::Malformed(format!(
                "запись после ServerHello несёт тип {inner_type:#04x}, а не handshake (0x16)"
            )));
        }
        handshake_buffer.extend_from_slice(&plaintext);

        while let Some((message_type, message_body, consumed)) =
            take_handshake_message(&handshake_buffer)?
        {
            let message_bytes = handshake_buffer[..consumed].to_vec();
            let message_body = message_body.to_vec();
            handshake_buffer.drain(..consumed);

            match message_type {
                HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS => {
                    seen_encrypted_extensions = true;
                    messages_before_finished.extend_from_slice(&message_bytes);
                }
                HANDSHAKE_TYPE_CERTIFICATE => {
                    if !seen_encrypted_extensions {
                        return Err(RealityError::Malformed(
                            "Certificate раньше EncryptedExtensions".to_owned(),
                        ));
                    }
                    verify_certificate_message(&message_body, auth_key)?;
                    seen_certificate = true;
                    messages_before_finished.extend_from_slice(&message_bytes);
                }
                HANDSHAKE_TYPE_CERTIFICATE_VERIFY => {
                    if !seen_certificate {
                        return Err(RealityError::Malformed(
                            "CertificateVerify раньше Certificate".to_owned(),
                        ));
                    }
                    messages_before_finished.extend_from_slice(&message_bytes);
                }
                HANDSHAKE_TYPE_FINISHED => {
                    if !seen_certificate {
                        return Err(RealityError::Malformed(
                            "Finished сервера раньше Certificate".to_owned(),
                        ));
                    }
                    return Ok(ServerFlight {
                        messages_before_finished,
                        server_finished_message: message_bytes,
                        verify_data: message_body,
                    });
                }
                _ => {} // NewSessionTicket сюда не попадает: он идёт после Finished, под прикладными ключами (application.rs).
            }
        }
    }
}

/// Читает записи рукопожатия, пока не разберёт `Certificate`, и проверяет
/// его. `EncryptedExtensions` перед ним читается и отбрасывается — этому шагу
/// нужен только сертификат.
async fn read_certificate_and_verify<S>(
    io: &mut S,
    record_key: &mut RecordKey,
    auth_key: &[u8; 32],
) -> Result<Verified, RealityError>
where
    S: AsyncRead + Unpin,
{
    let mut handshake_buffer = Vec::new();
    let mut seen_encrypted_extensions = false;

    loop {
        let (header, mut body) = read_record(io).await?;
        match header[0] {
            CONTENT_TYPE_CHANGE_CIPHER_SPEC => continue,
            CONTENT_TYPE_APPLICATION_DATA => {}
            other => {
                return Err(RealityError::Malformed(format!(
                    "тип записи {other:#04x} вместо application_data (0x17) или \
                     change_cipher_spec (0x14)"
                )));
            }
        }

        let (inner_type, plaintext) = record_key.open(&header, &mut body)?;
        if inner_type != crate::reality::record::CONTENT_TYPE_HANDSHAKE {
            return Err(RealityError::Malformed(format!(
                "запись после ServerHello несёт тип {inner_type:#04x}, а не handshake (0x16)"
            )));
        }
        handshake_buffer.extend_from_slice(&plaintext);

        while let Some((message_type, message_body, consumed)) =
            take_handshake_message(&handshake_buffer)?
        {
            // Тело сообщения копируется до `drain`: `handshake_buffer` нужен
            // мутабельно для удаления разобранных байт, а `message_body`
            // заимствован из него же — владеющая копия развязывает эти два
            // заимствования.
            let message_body = message_body.to_vec();
            handshake_buffer.drain(..consumed);
            match message_type {
                HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS => seen_encrypted_extensions = true,
                HANDSHAKE_TYPE_CERTIFICATE => {
                    if !seen_encrypted_extensions {
                        return Err(RealityError::Malformed(
                            "Certificate раньше EncryptedExtensions".to_owned(),
                        ));
                    }
                    return verify_certificate_message(&message_body, auth_key);
                }
                _ => {} // остальное (например, запрос клиентского сертификата) не наша забота.
            }
        }
    }
}

/// Тип сообщения, его тело и сколько байт буфера оно заняло целиком (с
/// заголовком) — то, что возвращает [`take_handshake_message`].
type HandshakeMessage<'a> = (u8, &'a [u8], usize);

/// Один шаг чтения сообщения рукопожатия из накопленного буфера: заголовок (1
/// байт типа + 3 байта длины, RFC 8446 §4) и тело. `None` — данных пока не
/// хватает, это нормально для потока.
fn take_handshake_message(buffer: &[u8]) -> Result<Option<HandshakeMessage<'_>>, RealityError> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    let message_type = buffer[0];
    let length = u32::from_be_bytes([0, buffer[1], buffer[2], buffer[3]]) as usize;
    let total = 4 + length;
    if buffer.len() < total {
        return Ok(None);
    }
    Ok(Some((message_type, &buffer[4..total], total)))
}

/// Разбирает `Certificate` (RFC 8446 §4.4.2) и проверяет первый сертификат.
///
/// ```text
/// Certificate {
///     opaque certificate_request_context<0..2^8-1>;
///     CertificateEntry certificate_list<0..2^24-1>;
/// }
/// CertificateEntry { opaque cert_data<1..2^24-1>; Extensions extensions<0..2^16-1>; }
/// ```
fn verify_certificate_message(body: &[u8], auth_key: &[u8; 32]) -> Result<Verified, RealityError> {
    let context_len = *body
        .first()
        .ok_or(RealityError::Malformed("Certificate пуст".to_owned()))?
        as usize;
    let after_context = body.get(1 + context_len..).ok_or(RealityError::Malformed(
        "Certificate короче, чем требует context".to_owned(),
    ))?;
    let list_len_bytes = after_context
        .get(..3)
        .ok_or(RealityError::Malformed("нет длины cert_list".to_owned()))?;
    let list_len =
        u32::from_be_bytes([0, list_len_bytes[0], list_len_bytes[1], list_len_bytes[2]]) as usize;
    let list = after_context
        .get(3..3 + list_len)
        .ok_or(RealityError::Malformed(
            "cert_list короче заявленного".to_owned(),
        ))?;

    let cert_data_len_bytes = list
        .get(..3)
        .ok_or(RealityError::Malformed("cert_list пуст".to_owned()))?;
    let cert_data_len = u32::from_be_bytes([
        0,
        cert_data_len_bytes[0],
        cert_data_len_bytes[1],
        cert_data_len_bytes[2],
    ]) as usize;
    let der = list
        .get(3..3 + cert_data_len)
        .ok_or(RealityError::Malformed(
            "cert_data короче заявленного".to_owned(),
        ))?;

    let leaf = certificate::parse_leaf(der)?;
    match leaf.ed25519_public_key {
        Some(pubkey) if auth::verify_certificate(auth_key, &pubkey, &leaf.signature) => {
            Ok(Verified)
        }
        _ => Err(RealityError::NotRecognized),
    }
}

/// Читает одну TLS-запись целиком: 5-байтный заголовок и тело заявленной
/// длины.
async fn read_record<S>(io: &mut S) -> Result<([u8; 5], Vec<u8>), RealityError>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; 5];
    io.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; len];
    io.read_exact(&mut body).await?;
    Ok((header, body))
}

/// Читает `ServerHello`, накапливая байты, пока не придёт целая запись.
/// Возвращает разобранное сообщение и его байты без заголовка записи (нужны
/// как часть транскрипта, `key_schedule::transcript_hash`).
async fn read_server_hello<S>(io: &mut S) -> Result<(ServerHello, Vec<u8>), RealityError>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(256);
    loop {
        if let Some(total) = penguin_utls::server_hello::record_len(&buffer)
            .map_err(|e| RealityError::Malformed(e.to_string()))?
            && buffer.len() >= total
        {
            let hello = penguin_utls::server_hello::parse(&buffer[..total])
                .map_err(|e| RealityError::Malformed(e.to_string()))?;
            return Ok((hello, buffer[5..total].to_vec()));
        }

        let mut chunk = [0u8; 512];
        let read = io.read(&mut chunk).await?;
        if read == 0 {
            return Err(RealityError::Malformed(
                "соединение закрылось раньше ServerHello".to_owned(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

/// Текущее время в секундах Unix, как ждёт `SessionID` (`auth.rs`).
///
/// Часы до `UNIX_EPOCH` — не наш случай (система без верной даты не сможет
/// пройти вообще ничего в TLS, не только Reality); `unwrap_or` на этот
/// случай честнее паники и не требует протаскивать ошибку через всю
/// сборку `ClientHello`.
fn current_unix_time() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_handshake_message_waits_for_the_full_body() {
        let mut buffer = vec![0x08, 0x00, 0x00, 0x03, 1, 2];
        assert!(
            take_handshake_message(&buffer)
                .expect("не сломано")
                .is_none(),
            "тело ещё не пришло целиком (нужно 3 байта, есть 2)"
        );
        buffer.push(3);
        let (message_type, body, consumed) = take_handshake_message(&buffer)
            .expect("не сломано")
            .expect("тело пришло");
        assert_eq!(message_type, 0x08);
        assert_eq!(body, &[1, 2, 3]);
        assert_eq!(consumed, 7);
    }

    #[test]
    fn the_hello_retry_request_constant_is_sha256_of_its_name() {
        // Пересчитан независимо от источника, где взят (см. документ
        // модуля): SHA-256("HelloRetryRequest").
        let digest = ring::digest::digest(&ring::digest::SHA256, b"HelloRetryRequest");
        assert_eq!(digest.as_ref(), HELLO_RETRY_REQUEST_RANDOM);
    }

    #[test]
    fn a_certificate_message_with_a_context_is_rejected_cleanly() {
        // certificate_request_context длиной 1 — TLS 1.3 разрешает его
        // только в сообщениях client Certificate, серверный обязан слать
        // context_len = 0; этот код его просто пропустит по длине, не
        // разбирая, — проверяем, что укороченный буфер не паникует.
        let body = [1u8]; // заявлена длина контекста 1, а самого байта нет
        let err = verify_certificate_message(&body, &[0; 32]).expect_err("буфер короче");
        assert!(err.to_string().contains("context"));
    }

    #[test]
    fn garbage_certificate_bodies_are_refused_not_panicked_on() {
        for len in 0..16 {
            let body = vec![0xFFu8; len];
            let _ = verify_certificate_message(&body, &[0; 32]);
        }
    }

    /// Один блок рукопожатия: тип и трёхбайтная длина (RFC 8446 §4), затем
    /// тело — то же самое, что строит [`penguin_utls`] у `ClientHello`.
    fn build_handshake_message(message_type: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![message_type];
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        out.extend_from_slice(body);
        out
    }

    /// Тело сообщения `Certificate` (RFC 8446 §4.4.2) с одним самоподписанным
    /// сертификатом: минимальный DER, в котором есть только то, что читает
    /// `certificate::parse_leaf` — `SubjectPublicKeyInfo` на `Ed25519` и
    /// `signatureValue`. Настоящий сертификат несёт куда больше полей;
    /// разбору (и, значит, этому тесту) они не нужны.
    fn build_certificate_message(pubkey: [u8; 32], signature: &[u8]) -> Vec<u8> {
        let oid = [0x06, 0x03, 0x2b, 0x65, 0x70]; // id-Ed25519, RFC 8410 §3
        let mut algorithm = vec![0x30, oid.len() as u8];
        algorithm.extend_from_slice(&oid);

        let mut bit_string_content = vec![0x00];
        bit_string_content.extend_from_slice(&pubkey);
        let mut public_key_bit_string = vec![0x03, bit_string_content.len() as u8];
        public_key_bit_string.extend_from_slice(&bit_string_content);

        let mut spki_content = algorithm;
        spki_content.extend_from_slice(&public_key_bit_string);
        let mut spki = vec![0x30, spki_content.len() as u8];
        spki.extend_from_slice(&spki_content);

        let signature_algorithm = vec![0x30, 0x00]; // пустая SEQUENCE — не разбирается
        let mut signature_bit_string_content = vec![0x00];
        signature_bit_string_content.extend_from_slice(signature);
        let mut signature_bit_string = vec![0x03, signature_bit_string_content.len() as u8];
        signature_bit_string.extend_from_slice(&signature_bit_string_content);

        // tbsCertificate здесь — сам SPKI: parse_leaf ищет его рекурсивно по
        // всему телу Certificate, а не по фиксированному месту.
        let mut certificate_content = spki;
        certificate_content.extend_from_slice(&signature_algorithm);
        certificate_content.extend_from_slice(&signature_bit_string);
        let mut der = vec![0x30, certificate_content.len() as u8];
        der.extend_from_slice(&certificate_content);

        let mut entry = Vec::new();
        entry.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
        entry.extend_from_slice(&der);
        entry.extend_from_slice(&[0x00, 0x00]); // extensions_len = 0

        let mut body = vec![0x00]; // certificate_request_context длиной 0
        body.extend_from_slice(&(entry.len() as u32).to_be_bytes()[1..]);
        body.extend_from_slice(&entry);
        body
    }

    #[tokio::test]
    async fn read_server_flight_collects_the_transcript_and_verifies_the_certificate() {
        let cipher = CipherSuite::Aes128GcmSha256;
        let key = [7u8; 16];
        let iv = [1u8; 12];
        let mut sender = RecordKey::new(cipher, &key, iv).expect("ключ строится");
        let mut reader = RecordKey::new(cipher, &key, iv).expect("ключ строится");

        let auth_key = [9u8; 32];
        let pubkey = [3u8; 32];
        let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, &auth_key);
        let signature = ring::hmac::sign(&hmac_key, &pubkey);

        let encrypted_extensions =
            build_handshake_message(HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, &[]);
        let certificate = build_handshake_message(
            HANDSHAKE_TYPE_CERTIFICATE,
            &build_certificate_message(pubkey, signature.as_ref()),
        );
        let certificate_verify =
            build_handshake_message(HANDSHAKE_TYPE_CERTIFICATE_VERIFY, &[0xAA; 4]);
        let finished_body = vec![0xEEu8; 32];
        let finished = build_handshake_message(HANDSHAKE_TYPE_FINISHED, &finished_body);

        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&encrypted_extensions);
        plaintext.extend_from_slice(&certificate);
        plaintext.extend_from_slice(&certificate_verify);
        plaintext.extend_from_slice(&finished);

        let record = sender
            .seal(CONTENT_TYPE_HANDSHAKE, &plaintext)
            .expect("шифруется");

        let (mut wire, mut peer) = tokio::io::duplex(8192);
        wire.write_all(&record).await.expect("пишется");

        let flight = read_server_flight(&mut peer, &mut reader, &auth_key)
            .await
            .expect("разбирается и сертификат проходит проверку");

        let mut expected_before = Vec::new();
        expected_before.extend_from_slice(&encrypted_extensions);
        expected_before.extend_from_slice(&certificate);
        expected_before.extend_from_slice(&certificate_verify);
        assert_eq!(flight.messages_before_finished, expected_before);
        assert_eq!(flight.server_finished_message, finished);
        assert_eq!(flight.verify_data, finished_body);
    }

    #[tokio::test]
    async fn read_server_flight_rejects_a_certificate_with_the_wrong_auth_key() {
        let cipher = CipherSuite::Aes128GcmSha256;
        let key = [7u8; 16];
        let iv = [1u8; 12];
        let mut sender = RecordKey::new(cipher, &key, iv).expect("ключ строится");
        let mut reader = RecordKey::new(cipher, &key, iv).expect("ключ строится");

        let pubkey = [3u8; 32];
        // Подпись посчитана другим AuthKey — как будто SessionID не подошёл
        // серверу (`RealityError::NotRecognized`), а не как повреждение TLS.
        let wrong_hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, &[1u8; 32]);
        let signature = ring::hmac::sign(&wrong_hmac_key, &pubkey);

        let plaintext = build_handshake_message(HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, &[])
            .into_iter()
            .chain(build_handshake_message(
                HANDSHAKE_TYPE_CERTIFICATE,
                &build_certificate_message(pubkey, signature.as_ref()),
            ))
            .collect::<Vec<u8>>();

        let record = sender
            .seal(CONTENT_TYPE_HANDSHAKE, &plaintext)
            .expect("шифруется");

        let (mut wire, mut peer) = tokio::io::duplex(8192);
        wire.write_all(&record).await.expect("пишется");

        let auth_key = [9u8; 32];
        let err = read_server_flight(&mut peer, &mut reader, &auth_key)
            .await
            .expect_err("подпись не сходится с этим AuthKey");
        assert!(matches!(err, RealityError::NotRecognized));
    }
}
