//! Заголовок ответа: `AEAD длины (18) | AEAD заголовка (N+16)`.
//!
//! Открытый: `байт ответа | настройки | команда | данные команды`. Ключи выводятся из ключа и
//! `IV` тела ответа, без AAD (`DecodeResponseHeader`, `proxy/vmess/encoding/client.go`,
//! `v2fly/v2ray-core`). Команды (`CommandSwitchAccount`) не исполняются, данные отбрасываются.

use crate::crypto::aes_gcm;
use crate::crypto::kdf::{kdf, kdf16};
use crate::error::{VmessError, VmessResult};

/// Блок длины: два байта плюс метка.
pub const LENGTH_BLOCK_LEN: usize = 2 + 16;

const LABEL_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const LABEL_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const LABEL_KEY: &[u8] = b"AEAD Resp Header Key";
const LABEL_IV: &[u8] = b"AEAD Resp Header IV";

/// Расшифровывает блок длины; возвращает длину заголовка без метки.
pub fn open_length(
    response_body_key: &[u8; 16],
    response_body_iv: &[u8; 16],
    block: &mut [u8; LENGTH_BLOCK_LEN],
) -> VmessResult<u16> {
    let key = kdf16(response_body_key, &[LABEL_LEN_KEY]);
    let nonce = nonce12(response_body_iv, LABEL_LEN_IV);
    let plain = aes_gcm::open(&key, &nonce, &[], block)?;

    let raw: [u8; 2] = plain
        .try_into()
        .map_err(|_| VmessError::malformed("длина заголовка ответа не в два байта"))?;
    Ok(u16::from_be_bytes(raw))
}

/// Расшифровывает заголовок (`length + 16` байт); несовпавший байт ответа — [`VmessError::AuthRejected`].
pub fn open_payload<'a>(
    response_body_key: &[u8; 16],
    response_body_iv: &[u8; 16],
    response_header: u8,
    block: &'a mut [u8],
) -> VmessResult<&'a [u8]> {
    let key = kdf16(response_body_key, &[LABEL_KEY]);
    let nonce = nonce12(response_body_iv, LABEL_IV);
    let plain = aes_gcm::open(&key, &nonce, &[], block)?;

    match plain.first() {
        Some(&byte) if byte == response_header => Ok(plain),
        Some(_) => Err(VmessError::AuthRejected),
        None => Err(VmessError::malformed("заголовок ответа пуст")),
    }
}

/// Первые 12 байт вывода KDF — нонс AEAD.
fn nonce12(base: &[u8; 16], label: &[u8]) -> [u8; 12] {
    let full = kdf(base, &[label]);
    let mut out = [0u8; 12];
    out.copy_from_slice(&full[..12]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::security::Wire;
    use crate::crypto::session::Session;
    use crate::frame::request;

    /// Ответ сервера.
    fn seal_response(session: &Session, plain: &[u8]) -> Vec<u8> {
        let len_key = kdf16(&session.response_body_key, &[LABEL_LEN_KEY]);
        let len_nonce = nonce12(&session.response_body_iv, LABEL_LEN_IV);
        let sealed_len = aes_gcm::seal(
            &len_key,
            &len_nonce,
            &[],
            &u16::try_from(plain.len())
                .expect("тестовые данные короткие")
                .to_be_bytes(),
        )
        .expect("шифруется");

        let key = kdf16(&session.response_body_key, &[LABEL_KEY]);
        let nonce = nonce12(&session.response_body_iv, LABEL_IV);
        let sealed = aes_gcm::seal(&key, &nonce, &[], plain).expect("шифруется");

        let mut wire = sealed_len;
        wire.extend_from_slice(&sealed);
        wire
    }

    #[test]
    fn a_matching_header_byte_is_accepted() {
        let session = Session::new(Wire::Aes128Gcm);
        let plain = [session.response_header, 0, 0, 0];
        let mut wire = seal_response(&session, &plain);

        let mut length_block: [u8; LENGTH_BLOCK_LEN] =
            wire[..LENGTH_BLOCK_LEN].try_into().expect("длина верна");
        let length = open_length(
            &session.response_body_key,
            &session.response_body_iv,
            &mut length_block,
        )
        .expect("расшифровывается");
        assert_eq!(usize::from(length), plain.len());

        let payload = open_payload(
            &session.response_body_key,
            &session.response_body_iv,
            session.response_header,
            &mut wire[LENGTH_BLOCK_LEN..],
        )
        .expect("совпал");
        assert_eq!(payload, plain);
    }

    #[test]
    fn a_mismatched_header_byte_is_auth_rejected() {
        let session = Session::new(Wire::Aes128Gcm);
        let wrong_byte = session.response_header.wrapping_add(1);
        let plain = [wrong_byte, 0, 0, 0];
        let mut wire = seal_response(&session, &plain);

        let mut length_block: [u8; LENGTH_BLOCK_LEN] =
            wire[..LENGTH_BLOCK_LEN].try_into().expect("длина верна");
        open_length(
            &session.response_body_key,
            &session.response_body_iv,
            &mut length_block,
        )
        .expect("расшифровывается");

        let err = open_payload(
            &session.response_body_key,
            &session.response_body_iv,
            session.response_header,
            &mut wire[LENGTH_BLOCK_LEN..],
        )
        .expect_err("не совпал");
        assert!(matches!(err, VmessError::AuthRejected));
    }

    #[test]
    fn a_request_session_round_trips_with_its_own_response() {
        let session = Session::new(Wire::Aes128Gcm);
        let _ = request::build(
            &"b831381d-6324-4d53-ad4f-8cda48b30811"
                .parse()
                .expect("разбирается"),
            &session,
            request::CMD_TCP,
            &penguin_core::address::SocketAddress::domain("example.com", 443),
        )
        .expect("собирается");

        let plain = [session.response_header, 0, 0, 0];
        let mut wire = seal_response(&session, &plain);
        let mut length_block: [u8; LENGTH_BLOCK_LEN] =
            wire[..LENGTH_BLOCK_LEN].try_into().expect("длина верна");
        open_length(
            &session.response_body_key,
            &session.response_body_iv,
            &mut length_block,
        )
        .expect("расшифровывается");
        open_payload(
            &session.response_body_key,
            &session.response_body_iv,
            session.response_header,
            &mut wire[LENGTH_BLOCK_LEN..],
        )
        .expect("совпал");
    }
}
