//! Сообщения сервера после `ServerHello`: под ключами рукопожатия, до прикладных ключей.

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::reality::error::RealityError;
use crate::reality::record::{
    CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE,
    RecordKey,
};
use crate::reality::{auth, certificate};

/// Типы сообщений рукопожатия (RFC 8446 §B.3).
pub(super) const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 8;
pub(super) const HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;
pub(super) const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 15;
pub(super) const HANDSHAKE_TYPE_FINISHED: u8 = 20;

/// Серверный полёт до `Finished` включительно, в исходных байтах (для транскрипта).
#[derive(Debug)]
pub(super) struct ServerFlight {
    /// `EncryptedExtensions` + `Certificate` + `CertificateVerify`.
    pub messages_before_finished: Vec<u8>,
    /// `Finished` целиком.
    pub server_finished_message: Vec<u8>,
    /// Тело `Finished`.
    pub verify_data: Vec<u8>,
}

/// Читает полёт до `Finished` сервера, не проверяя его. Сертификат проверяется HMAC из `auth.rs`;
/// подпись `CertificateVerify` нет: личность сервера доказывает этот HMAC, привязанный к нашим
/// `random` и `key_share`, а не самоподписанный сертификат сайта-прикрытия.
pub(super) async fn read_server_flight<S>(
    io: &mut S,
    record_key: &mut RecordKey,
    auth_key: &[u8; 32],
) -> Result<ServerFlight, RealityError>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut messages_before_finished = Vec::new();
    let mut seen_encrypted_extensions = false;
    let mut seen_certificate = false;

    loop {
        let message = next_message(io, record_key, &mut buffer).await?;
        match message[0] {
            HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS => {
                seen_encrypted_extensions = true;
                messages_before_finished.extend_from_slice(&message);
            }
            HANDSHAKE_TYPE_CERTIFICATE => {
                if !seen_encrypted_extensions {
                    return Err(malformed("Certificate раньше EncryptedExtensions"));
                }
                verify_certificate_message(&message[4..], auth_key)?;
                seen_certificate = true;
                messages_before_finished.extend_from_slice(&message);
            }
            HANDSHAKE_TYPE_CERTIFICATE_VERIFY => {
                if !seen_certificate {
                    return Err(malformed("CertificateVerify раньше Certificate"));
                }
                messages_before_finished.extend_from_slice(&message);
            }
            HANDSHAKE_TYPE_FINISHED => {
                if !seen_certificate {
                    return Err(malformed("Finished сервера раньше Certificate"));
                }
                return Ok(ServerFlight {
                    messages_before_finished,
                    verify_data: message[4..].to_vec(),
                    server_finished_message: message,
                });
            }
            _ => {}
        }
    }
}

/// Читает полёт до `Certificate` и проверяет его; остальное не нужно.
pub(super) async fn read_certificate_and_verify<S>(
    io: &mut S,
    record_key: &mut RecordKey,
    auth_key: &[u8; 32],
) -> Result<(), RealityError>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut seen_encrypted_extensions = false;

    loop {
        let message = next_message(io, record_key, &mut buffer).await?;
        match message[0] {
            HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS => seen_encrypted_extensions = true,
            HANDSHAKE_TYPE_CERTIFICATE => {
                if !seen_encrypted_extensions {
                    return Err(malformed("Certificate раньше EncryptedExtensions"));
                }
                return verify_certificate_message(&message[4..], auth_key);
            }
            _ => {}
        }
    }
}

fn malformed(text: &str) -> RealityError {
    RealityError::Malformed(text.to_owned())
}

/// Следующее сообщение рукопожатия целиком (с заголовком); `buffer` копит остаток записи.
async fn next_message<S>(
    io: &mut S,
    record_key: &mut RecordKey,
    buffer: &mut Vec<u8>,
) -> Result<Vec<u8>, RealityError>
where
    S: AsyncRead + Unpin,
{
    loop {
        if let Some((_, _, consumed)) = take_handshake_message(buffer)? {
            return Ok(buffer.drain(..consumed).collect());
        }

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

        let (inner_type, plaintext) = record_key.open_in_place(&header, &mut body)?;
        if inner_type != CONTENT_TYPE_HANDSHAKE {
            return Err(RealityError::Malformed(format!(
                "запись после ServerHello несёт тип {inner_type:#04x}, а не handshake (0x16)"
            )));
        }
        buffer.extend_from_slice(plaintext);
    }
}

/// Тип, тело и полная длина сообщения в буфере.
type HandshakeMessage<'a> = (u8, &'a [u8], usize);

/// Первое целое сообщение буфера (тип 1 + длина 3 + тело, RFC 8446 §4); `None` — не хватает байт.
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

/// Читает `Certificate` (RFC 8446 §4.4.2) и проверяет первый сертификат.
fn verify_certificate_message(body: &[u8], auth_key: &[u8; 32]) -> Result<(), RealityError> {
    let context_len = *body
        .first()
        .ok_or(RealityError::Malformed("Certificate пуст".to_owned()))?
        as usize;
    let after_context = body.get(1 + context_len..).ok_or(RealityError::Malformed(
        "Certificate короче, чем требует context".to_owned(),
    ))?;
    let list = length_prefixed(
        after_context,
        "нет длины cert_list",
        "cert_list короче заявленного",
    )?;
    let der = length_prefixed(list, "cert_list пуст", "cert_data короче заявленного")?;

    let leaf = certificate::parse_leaf(der)?;
    match leaf.ed25519_public_key {
        Some(pubkey) if auth::verify_certificate(auth_key, &pubkey, &leaf.signature) => Ok(()),
        _ => Err(RealityError::NotRecognized),
    }
}

/// Поле с трёхбайтной длиной в начале.
fn length_prefixed<'a>(
    data: &'a [u8],
    no_length: &str,
    too_short: &str,
) -> Result<&'a [u8], RealityError> {
    let prefix = data.get(..3).ok_or_else(|| malformed(no_length))?;
    let len = u32::from_be_bytes([0, prefix[0], prefix[1], prefix[2]]) as usize;
    data.get(3..3 + len).ok_or_else(|| malformed(too_short))
}

/// Одна запись целиком: заголовок и тело.
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

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::reality::cipher_suite::CipherSuite;

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
    fn a_certificate_message_with_a_context_is_rejected_cleanly() {
        let body = [1u8];
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

    /// Сообщение рукопожатия: тип, трёхбайтная длина, тело.
    fn build_handshake_message(message_type: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![message_type];
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        out.extend_from_slice(body);
        out
    }

    /// Тело `Certificate` с минимальным DER: только Ed25519 SPKI и `signatureValue`.
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

        let signature_algorithm = vec![0x30, 0x00];
        let mut signature_bit_string_content = vec![0x00];
        signature_bit_string_content.extend_from_slice(signature);
        let mut signature_bit_string = vec![0x03, signature_bit_string_content.len() as u8];
        signature_bit_string.extend_from_slice(&signature_bit_string_content);

        // tbsCertificate — сам SPKI: `parse_leaf` ищет его по всему телу.
        let mut certificate_content = spki;
        certificate_content.extend_from_slice(&signature_algorithm);
        certificate_content.extend_from_slice(&signature_bit_string);
        let mut der = vec![0x30, certificate_content.len() as u8];
        der.extend_from_slice(&certificate_content);

        let mut entry = Vec::new();
        entry.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
        entry.extend_from_slice(&der);
        entry.extend_from_slice(&[0x00, 0x00]);

        let mut body = vec![0x00];
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
