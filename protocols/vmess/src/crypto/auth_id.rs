//! Опознаватель заголовка: шестнадцать байт, которыми сервер узнаёт клиента
//! без единого открытого поля в запросе.
//!
//! ```text
//!  время (8, big-endian) | случайные (4) | CRC32 первых двенадцати (4)
//!  └──────────────────────────── 16 байт открытым текстом ─────────────────┘
//!                                   │
//!                                   │  AES-128, один блок, режим ECB
//!                                   │  ключ = KDF16(cmdKey, "AES Auth ID Encryption")
//!                                   ▼
//!                          опознаватель (16 байт на проводе)
//! ```
//!
//! Блок ровно один — шестнадцать байт как раз укладываются в размер блока
//! AES, и режим сцепления просто не успевает понадобиться: это разовое
//! шифрование одного блока, а не поток.
//!
//! Метка времени — она же место, где сервер требует, чтобы часы не разошлись
//! больше чем на 120 секунд. Своего варианта ошибки у этого нет и быть не
//! может: сервер отвергает разошедшиеся часы тем же молчанием, что и неверный
//! UUID, — оба приходят как [`crate::error::VmessError::Disconnected`], и её
//! текст называет обе причины.

use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use rand::RngCore;

use crate::crypto::checksum::crc32;
use crate::crypto::kdf::kdf16;

/// Метка KDF для ключа шифрования опознавателя.
const LABEL_AUTH_ID_KEY: &[u8] = b"AES Auth ID Encryption";

/// Собирает опознаватель заголовка по `cmdKey` и текущему времени Unix.
pub fn create(cmd_key: &[u8; 16], unix_time: i64) -> [u8; 16] {
    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&unix_time.to_be_bytes());
    rand::thread_rng().fill_bytes(&mut plain[8..12]);
    let check = crc32(&plain[..12]);
    plain[12..].copy_from_slice(&check.to_be_bytes());

    // Ключ и блок фиксированной длины 16 байт — размер задан константой
    // массива, а не пользовательским вводом, и `KeyInit::new` здесь не может
    // отказать.
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
        // Четыре случайных байта делают повторный опознаватель маловероятным
        // даже в одну и ту же секунду — проверяем хотя бы это, не саму
        // энтропию генератора.
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
