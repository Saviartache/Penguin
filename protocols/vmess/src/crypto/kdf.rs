//! Вложенный HMAC-SHA256 — «VMess AEAD KDF».
//!
//! Стандартным HKDF это не выражается, и `ring` его не считает: у HKDF один
//! слой HMAC, а здесь их несколько, и хеш-функцией каждого следующего слоя
//! служит целиком предыдущий, а не его выход.
//!
//! ```text
//! H0(x) = SHA256(x)
//! H1(x) = HMAC(key = "VMess AEAD KDF", hash = H0, x)
//! H2(x) = HMAC(key = labels[0],        hash = H1, x)
//! ...
//! Hn(x) = HMAC(key = labels[n-1],      hash = H(n-1), x)
//! KDF(key, labels) = Hn(key)
//! ```
//!
//! Основание `"VMess AEAD KDF"` — ключ самого первого слоя HMAC, а не метка
//! домена в общем ряду; оно неявное и есть у любого вызова. Дальше каждая
//! строка из `labels` становится ключом следующего слоя, а исходный `key` —
//! сообщением, которое хеширует самый внешний слой.
//!
//! Проверено внешним вектором из `proxy/vmess/aead/kdf_test.go` эталона
//! (`v2fly/v2ray-core`, `master`): `KDFValue` со входом `"Demo Key for KDF
//! Value Test"` и тремя метками `"Demo Path for KDF Value Test"` (с номерами
//! 2 и 3 у второй и третьей) даёт ровно то значение, что зашито в тест ниже.

use sha2::{Digest, Sha256};

/// Основание — ключ самого внешнего вызова `SHA256`, а не метка домена.
const BASE_KEY: &[u8] = b"VMess AEAD KDF";

/// Длина блока `SHA-256` — она же длина набивки ключа HMAC на каждом слое,
/// независимо от того, что этот слой хеширует на самом деле.
const BLOCK_LEN: usize = 64;

/// Выводит ключ вложенным HMAC-SHA256: основание плюс цепочка меток.
///
/// Возвращает все 32 байта: часть вызовов режет их до 16
/// ([`kdf16`]), часть берёт первые 12 как нонс AEAD.
pub fn kdf(key: &[u8], labels: &[&[u8]]) -> [u8; 32] {
    // Основание — ключ самого первого слоя HMAC, а не метка после него:
    // `hash_at(1, ..)` обязан быть HMAC-SHA256, keyed именно этой строкой.
    let mut keys = Vec::with_capacity(labels.len() + 1);
    keys.push(BASE_KEY);
    keys.extend_from_slice(labels);
    hash_at(keys.len(), &keys, key)
}

/// То же самое, обрезанное до 16 байт — так эталон готовит ключи AES.
pub fn kdf16(key: &[u8], labels: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, labels);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Хеш-функция слоя `depth`: `0` — голый `SHA-256`, дальше — HMAC с ключом
/// `labels[depth - 1]`, чья собственная хеш-функция — слой `depth - 1`.
///
/// Рекурсия глубиной в две-три метки — цена вложенности, которую эталон
/// платит на каждый вызов KDF; сам вызов происходит не чаще раза на
/// заголовок или на рукопожатие, а не на кусок тела.
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
        // `proxy/vmess/aead/kdf_test.go`, `TestKDFValue` — единственный
        // опубликованный вектор на эту функцию, а не наш собственный расчёт.
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
        // Основание не передаётся в `labels` — вызов без меток уже отличает
        // это KDF от голого HMAC-SHA256 с тем же ключом.
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
