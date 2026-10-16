//! Вложенный HMAC-SHA256 "VMess AEAD KDF" (`ring::hmac` не принимает свою хеш-функцию).
//!
//! `H0 = SHA256`, `Hi(x) = HMAC(key = keys[i-1], hash = H(i-1), x)`,
//! `keys = ["VMess AEAD KDF", labels...]`, `KDF(key, labels) = Hn(key)`.
//! Вектор из `proxy/vmess/aead/kdf_test.go` (`v2fly/v2ray-core`) в тесте ниже.

use sha2::{Digest, Sha256};

/// Ключ самого первого слоя HMAC.
const BASE_KEY: &[u8] = b"VMess AEAD KDF";

/// Длина блока `SHA-256` и набивки ключа HMAC.
const BLOCK_LEN: usize = 64;

/// Все 32 байта вывода; вызывается раз на заголовок, не на кадр.
pub fn kdf(key: &[u8], labels: &[&[u8]]) -> [u8; 32] {
    let mut keys = Vec::with_capacity(labels.len() + 1);
    keys.push(BASE_KEY);
    keys.extend_from_slice(labels);
    hash_at(keys.len(), &keys, key)
}

/// Первые 16 байт [`kdf`]: ключи AES.
pub fn kdf16(key: &[u8], labels: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, labels);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Хеш слоя `depth`: `0` — `SHA-256`, иначе HMAC с ключом `labels[depth - 1]` поверх слоя `depth - 1`.
fn hash_at(depth: usize, labels: &[&[u8]], data: &[u8]) -> [u8; 32] {
    if depth == 0 {
        return Sha256::digest(data).into();
    }

    let hmac_key = labels[depth - 1];
    let mut padded = [0u8; BLOCK_LEN];
    if hmac_key.len() > BLOCK_LEN {
        padded[..32].copy_from_slice(&hash_at(depth - 1, labels, hmac_key));
    } else {
        padded[..hmac_key.len()].copy_from_slice(hmac_key);
    }

    let mut inner_input = Vec::with_capacity(BLOCK_LEN + data.len());
    inner_input.extend(padded.map(|b| b ^ 0x36));
    inner_input.extend_from_slice(data);
    let inner = hash_at(depth - 1, labels, &inner_input);

    let mut outer_input = Vec::with_capacity(BLOCK_LEN + inner.len());
    outer_input.extend(padded.map(|b| b ^ 0x5c));
    outer_input.extend_from_slice(&inner);
    hash_at(depth - 1, labels, &outer_input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_reference_test_vector() {
        let got = kdf(
            b"Demo Key for KDF Value Test",
            &[
                b"Demo Path for KDF Value Test",
                b"Demo Path for KDF Value Test2",
                b"Demo Path for KDF Value Test3",
            ],
        );
        let expected = hex("53e9d7e1bd7bd25022b71ead07d8a596efc8a845c7888652fd684b4903dc8892");
        assert_eq!(got.to_vec(), expected);
    }

    #[test]
    fn kdf16_takes_the_first_half() {
        let full = kdf(b"key", &[b"label"]);
        let short = kdf16(b"key", &[b"label"]);
        assert_eq!(&full[..16], &short[..]);
    }

    #[test]
    fn a_different_label_gives_a_different_key() {
        let a = kdf(b"key", &[b"one"]);
        let b = kdf(b"key", &[b"two"]);
        assert_ne!(a, b);
    }

    #[test]
    fn the_base_is_implicit_not_a_label() {
        let ours = kdf(b"key", &[]);
        let plain = Sha256::digest(b"key");
        assert_ne!(ours.to_vec(), plain.to_vec());
    }

    /// Разбирает hex-строку теста в байты — без внешней зависимости.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("тестовый вектор верен"))
            .collect()
    }
}
