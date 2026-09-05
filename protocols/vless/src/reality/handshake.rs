//! Ведёт рукопожатие Reality до места, где сервер можно проверить, — и
//! останавливается там же.
//!
//! ```text
//! клиент                                              сервер
//!   │                                                     │
//!   │  ClientHello (SessionID = зашифрованные            │
//!   │  данные опознания, auth.rs)          ─────────────>│
//!   │                                                     │
//!   │<───────────────────────────  ServerHello (открыто) │
//!   │                                                     │
//!   │  вывод ключа записи рукопожатия сервера            │
//!   │  (key_schedule.rs) из общего секрета (EC)DHE       │
//!   │  настоящего TLS 1.3 — НЕ AuthKey Reality           │
//!   │                                                     │
//!   │<──── EncryptedExtensions, Certificate (зашифровано, │
//!   │      record.rs расшифровывает по мере поступления) │
//!   │                                                     │
//!   │  certificate.rs: ключ Ed25519 + подпись            │
//!   │  auth.rs: HMAC-SHA512(AuthKey, ключ) == подпись?    │
//!   │                                                     │
//!  Verified                                     NotRecognized
//! ```
//!
//! **Дальше рукопожатие не идёт.** `CertificateVerify` и `Finished` сервера
//! не разбираются, свой `Finished` не отправляется, прикладные ключи не
//! выводятся — соединение остаётся непригодным для передачи байт VLESS.
//! Довести его до конца — отдельная задача (полноценный TLS 1.3 поверх
//! своего рукопожатия, а затем XTLS Vision поверх него), которую этот шаг
//! фазы 19 не включает (см. `plan.md`, крайний пункт списка "чего это
//! требует", и `mod.rs`).
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

use crate::reality::cipher_suite::CipherSuite;
use crate::reality::config::RealityConfig;
use crate::reality::error::RealityError;
use crate::reality::record::{
    CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC, RecordKey,
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
}
