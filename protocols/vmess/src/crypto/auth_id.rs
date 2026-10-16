//! Опознаватель заголовка: `время(8) | случайные(4) | CRC32(4)`, один блок AES-128-ECB.
//!
//! Ключ — `KDF16(cmdKey, "AES Auth ID Encryption")`. Сервер отвергает разошедшиеся
//! больше чем на 120 с часы тем же молчанием, что и неверный UUID.

use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use penguin_proto::random;

use crate::crypto::checksum::crc32;
use crate::crypto::kdf::kdf16;

/// Метка KDF для ключа шифрования опознавателя.
const LABEL_AUTH_ID_KEY: &[u8] = b"AES Auth ID Encryption";

/// Собирает опознаватель по `cmdKey` и времени Unix.
pub fn create(cmd_key: &[u8; 16], unix_time: i64) -> [u8; 16] {
    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&unix_time.to_be_bytes());
    random::fill(&mut plain[8..12]);
    let check = crc32(&plain[..12]);
    plain[12..].copy_from_slice(&check.to_be_bytes());

    let key = kdf16(cmd_key, &[LABEL_AUTH_ID_KEY]);
    let cipher = Aes128::new(&key.into());
    let mut block = plain.into();
    cipher.encrypt_block(&mut block);
    block.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identifier_is_always_sixteen_bytes() {
        let id = create(&[7u8; 16], 1_700_000_000);
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn two_calls_do_not_repeat() {
        let a = create(&[1u8; 16], 1_700_000_000);
        let b = create(&[1u8; 16], 1_700_000_000);
        assert_ne!(a, b);
    }

    #[test]
    fn a_different_key_gives_a_different_identifier() {
        let a = create(&[1u8; 16], 1_700_000_000);
        let b = create(&[2u8; 16], 1_700_000_000);
        assert_ne!(a, b);
    }
}
