//! Рукопожатие Reality: [`verify`] доходит до `Certificate` сервера, [`connect`] — до прикладных ключей TLS 1.3.
//!
//! Клиент шлёт `ClientHello` с зашифрованными данными опознания в `SessionID` (`auth.rs`),
//! читает `ServerHello` и серверный полёт (`flight.rs`), сверяет `Finished`,
//! отвечает `ChangeCipherSpec` и своим `Finished`, выводит прикладные ключи.
//!
//! Прикладные секреты выводятся с транскриптом ДО `Finished` клиента, но ПОСЛЕ `Finished`
//! сервера (RFC 8446 §7.1). `HelloRetryRequest` не поддержан: сервер Reality отвечает `X25519`
//! сразу, а такой `random` отвергается как `Malformed`.

use penguin_core::address::Address;
use penguin_utls::{ClientHello, ServerHello};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::reality::application::RealityStream;
use crate::reality::cipher_suite::CipherSuite;
use crate::reality::config::RealityConfig;
use crate::reality::error::RealityError;
use crate::reality::flight::{self, HANDSHAKE_TYPE_FINISHED};
use crate::reality::record::{CONTENT_TYPE_HANDSHAKE, RecordKey};
use crate::reality::{auth, key_schedule};

/// Группа `X25519` в `key_share` (RFC 8446 §4.2.7).
const GROUP_X25519: u16 = 29;

/// `SHA-256("HelloRetryRequest")`: `ServerHello.random` такого вида — это `HelloRetryRequest` (RFC 8446 §4.1.3).
const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Сервер подтвердил себя как Reality; канал для VLESS ещё не готов.
#[derive(Debug, Clone, Copy)]
pub struct Verified;

/// Итог обмена `ClientHello`/`ServerHello`.
struct Negotiated {
    hello: ClientHello,
    auth_key: [u8; 32],
    cipher: CipherSuite,
    tls_shared_secret: [u8; 32],
    /// `ServerHello` без заголовка записи.
    server_hello: Vec<u8>,
}

impl Negotiated {
    /// Транскрипт `ClientHello..ServerHello` плюс `rest`.
    fn transcript(&self, rest: &[&[u8]]) -> Vec<u8> {
        let mut messages = vec![self.hello.handshake_bytes(), &self.server_hello];
        messages.extend_from_slice(rest);
        key_schedule::transcript_hash(self.cipher, &messages)
    }
}

/// Проверяет сертификат сервера на открытом соединении и останавливается.
pub async fn verify<S>(io: &mut S, config: &RealityConfig) -> Result<Verified, RealityError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let negotiated = negotiate(io, config).await?;
    let transcript = negotiated.transcript(&[]);
    let keys = key_schedule::server_handshake_traffic_keys(
        negotiated.cipher,
        &negotiated.tls_shared_secret,
        &transcript,
    )?;
    let mut record_key = RecordKey::new(negotiated.cipher, &keys.key, keys.iv)?;
    flight::read_certificate_and_verify(io, &mut record_key, &negotiated.auth_key).await?;
    Ok(Verified)
}

/// Ведёт рукопожатие до конца и отдаёт поток для байтов VLESS.
pub async fn connect<S>(mut io: S, config: &RealityConfig) -> Result<RealityStream<S>, RealityError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let negotiated = negotiate(&mut io, config).await?;
    let cipher = negotiated.cipher;
    let transcript_ch_sh = negotiated.transcript(&[]);

    let handshake_secret = key_schedule::handshake_secret(cipher, &negotiated.tls_shared_secret)?;
    let client_hs_secret = handshake_secret.traffic_secret("c hs traffic", &transcript_ch_sh)?;
    let server_hs_secret = handshake_secret.traffic_secret("s hs traffic", &transcript_ch_sh)?;
    let server_hs_keys = key_schedule::traffic_keys(cipher, &server_hs_secret)?;
    let client_hs_keys = key_schedule::traffic_keys(cipher, &client_hs_secret)?;
    let mut read_key = RecordKey::new(cipher, &server_hs_keys.key, server_hs_keys.iv)?;
    let mut write_key = RecordKey::new(cipher, &client_hs_keys.key, client_hs_keys.iv)?;

    let server_flight =
        flight::read_server_flight(&mut io, &mut read_key, &negotiated.auth_key).await?;

    let transcript_before_finished =
        negotiated.transcript(&[&server_flight.messages_before_finished]);
    let server_finished_key = key_schedule::finished_key(cipher, &server_hs_secret)?;
    if !key_schedule::verify_finished(
        cipher,
        &server_finished_key,
        &transcript_before_finished,
        &server_flight.verify_data,
    ) {
        return Err(RealityError::FinishedMismatch);
    }

    let transcript_through_finished = negotiated.transcript(&[
        &server_flight.messages_before_finished,
        &server_flight.server_finished_message,
    ]);

    let client_finished_key = key_schedule::finished_key(cipher, &client_hs_secret)?;
    let client_verify_data = key_schedule::finished_verify_data(
        cipher,
        &client_finished_key,
        &transcript_through_finished,
    );
    let mut client_finished = vec![HANDSHAKE_TYPE_FINISHED];
    client_finished.extend_from_slice(&(client_verify_data.len() as u32).to_be_bytes()[1..]);
    client_finished.extend_from_slice(&client_verify_data);

    // ChangeCipherSpec для мидлбоксов (RFC 8446 D.4): `SessionID` не пуст.
    io.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]).await?;
    let finished_record = write_key.seal(CONTENT_TYPE_HANDSHAKE, &client_finished)?;
    io.write_all(&finished_record).await?;
    io.flush().await?;

    let master_secret = handshake_secret.master_secret()?;
    let client_ap_secret =
        master_secret.traffic_secret("c ap traffic", &transcript_through_finished)?;
    let server_ap_secret =
        master_secret.traffic_secret("s ap traffic", &transcript_through_finished)?;
    let client_ap_keys = key_schedule::traffic_keys(cipher, &client_ap_secret)?;
    let server_ap_keys = key_schedule::traffic_keys(cipher, &server_ap_secret)?;

    Ok(RealityStream::new(
        io,
        RecordKey::new(cipher, &server_ap_keys.key, server_ap_keys.iv)?,
        RecordKey::new(cipher, &client_ap_keys.key, client_ap_keys.iv)?,
    ))
}

/// Отправляет `ClientHello` с данными опознания и разбирает `ServerHello`.
async fn negotiate<S>(io: &mut S, config: &RealityConfig) -> Result<Negotiated, RealityError>
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
    // Все отпечатки предлагают X25519 первым `key_share`; Reality другой группы не понимает.
    let x25519 = keys.first().ok_or_else(|| {
        RealityError::Config("отпечаток не запросил ни одного ключа key_share".to_owned())
    })?;
    let not_x25519 = || RealityError::Config("первый ключ ClientHello — не X25519".to_owned());

    let reality_shared_secret = x25519
        .x25519_diffie_hellman(&public_key)
        .ok_or_else(not_x25519)?;
    let auth_key = auth::derive_auth_key(&reality_shared_secret, &hello.random)?;
    let sealed = auth::seal_session_id(
        &auth_key,
        &hello.random,
        short_id,
        current_unix_time(),
        hello.handshake_bytes(),
    )?;
    hello.patch_session_id(sealed);

    io.write_all(&hello.record_bytes()).await?;
    io.flush().await?;

    let (server_hello, server_hello_message) = read_server_hello(io).await?;
    let (cipher, server_public) = check_server_hello(&server_hello)?;
    let tls_shared_secret = x25519
        .x25519_diffie_hellman(&server_public)
        .ok_or_else(not_x25519)?;

    Ok(Negotiated {
        hello,
        auth_key,
        cipher,
        tls_shared_secret,
        server_hello: server_hello_message,
    })
}

/// Шифр и ключ сервера, если `ServerHello` — TLS 1.3 с `X25519`.
fn check_server_hello(hello: &ServerHello) -> Result<(CipherSuite, [u8; 32]), RealityError> {
    if hello.random == HELLO_RETRY_REQUEST_RANDOM {
        return Err(RealityError::Malformed(
            "сервер запросил HelloRetryRequest — это не поддержано".to_owned(),
        ));
    }
    if hello.supported_version != Some(0x0304) {
        return Err(RealityError::UnsupportedNegotiation(format!(
            "supported_version = {:?} вместо TLS 1.3",
            hello.supported_version
        )));
    }
    let cipher = CipherSuite::from_u16(hello.cipher_suite).ok_or_else(|| {
        RealityError::UnsupportedNegotiation(format!(
            "шифр {:#06x} — не TLS 1.3",
            hello.cipher_suite
        ))
    })?;
    let key_share = hello
        .key_share
        .as_ref()
        .ok_or_else(|| RealityError::Malformed("ServerHello без key_share".to_owned()))?;
    if key_share.group != GROUP_X25519 {
        return Err(RealityError::UnexpectedGroup(key_share.group));
    }
    let public = key_share
        .data
        .as_slice()
        .try_into()
        .map_err(|_| RealityError::Malformed("key_share сервера — не 32 байта".to_owned()))?;
    Ok((cipher, public))
}

/// Читает `ServerHello`; возвращает разбор и байты без заголовка записи (для транскрипта).
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

/// Секунды Unix для `SessionID`; часы до эпохи дают 0.
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
    fn the_hello_retry_request_constant_is_sha256_of_its_name() {
        let digest = ring::digest::digest(&ring::digest::SHA256, b"HelloRetryRequest");
        assert_eq!(digest.as_ref(), HELLO_RETRY_REQUEST_RANDOM);
    }
}
