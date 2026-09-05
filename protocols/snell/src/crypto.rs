//! Вывод сеансового ключа: Argon2id прямо из пароля.
//!
//! ```text
//!  PSK ──┐
//!        ├── Argon2id(t=3, m=8 КиБ, p=1, 32 байта) ──► сеансовый ключ
//!  соль ─┘   (соль случайная, шестнадцать байт, на каждое соединение)
//! ```
//!
//! # Чем это отличается от Shadowsocks
//!
//! Всем. У Shadowsocks пароль сначала растягивается в главный ключ старой
//! функцией из OpenSSL, а сеансовый выводится из него и соли через HKDF. Здесь
//! главного ключа нет вовсе: Argon2id зовётся на каждое соединение прямо от
//! пароля и соли.
//!
//! # Про параметры
//!
//! Восемь килобайт памяти и три прохода — это очень мало для Argon2, который
//! придуман, чтобы стоить дорого. Выбирали их не мы: так считает сервер, и
//! любое другое число даёт другой ключ и молчащее соединение. Стойкость
//! здесь, как и у Shadowsocks, держится на длине пароля, а не на функции
//! вывода, — и это то, что интерфейс обязан понимать про короткий PSK.
//!
//! Числа сверены по двум независимым реализациям и по разбору протокола,
//! который называет их в терминах `libsodium`: `opslimit=3`,
//! `memlimit=0x2000` — те же три прохода и те же восемь килобайт.

use std::sync::Arc;

use argon2::{Algorithm as Argon2Algorithm, Argon2, Params, Version as Argon2Version};
use penguin_transport::aead::{Algorithm, Keying};
use penguin_transport::error::TransportError;

use crate::error::{SnellError, SnellResult};

/// Сколько байт соли уходит впереди потока.
///
/// Шестнадцать при любом шифре — в отличие от Shadowsocks, где длина соли
/// равна длине ключа.
pub const SALT_LEN: usize = 16;

/// Сколько проходов делает Argon2id.
pub const PASSES: u32 = 3;

/// Сколько килобайт памяти он занимает.
pub const MEMORY_KIB: u32 = 8;

/// Во сколько потоков считает.
pub const LANES: u32 = 1;

/// Сколько байт выдаёт вывод, прежде чем его обрежут под длину ключа.
pub const OUTPUT_LEN: usize = 32;

/// Выводит сеансовый ключ.
///
/// Длина ключа берётся у шифра: у AES-128 это первые шестнадцать байт вывода,
/// у ChaCha20 — все тридцать два.
pub fn session_key(psk: &str, salt: &[u8], algorithm: Algorithm) -> SnellResult<Vec<u8>> {
    let params = Params::new(MEMORY_KIB, PASSES, LANES, Some(OUTPUT_LEN))
        .map_err(|e| SnellError::crypto(format!("параметры Argon2: {e}")))?;
    let argon = Argon2::new(Argon2Algorithm::Argon2id, Argon2Version::V0x13, params);

    let mut out = vec![0u8; OUTPUT_LEN];
    argon
        .hash_password_into(psk.as_bytes(), salt, &mut out)
        .map_err(|e| SnellError::crypto(format!("вывод ключа: {e}")))?;

    out.truncate(algorithm.key_len());
    Ok(out)
}

/// Всё, что общему кадру нужно знать про ключи Snell.
pub fn keying(psk: String, algorithm: Algorithm) -> Keying {
    Keying::new(
        algorithm,
        SALT_LEN,
        Arc::new(move |salt: &[u8]| {
            session_key(&psk, salt, algorithm)
                .map_err(|err| TransportError::config(err.to_string()))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_is_as_long_as_the_cipher_wants() {
        for algorithm in [Algorithm::Aes128Gcm, Algorithm::ChaCha20Poly1305] {
            let key = session_key("psk", &[0u8; SALT_LEN], algorithm).expect("выводится");
            assert_eq!(key.len(), algorithm.key_len(), "{}", algorithm.name());
        }
    }

    #[test]
    fn the_short_key_is_the_beginning_of_the_long_one() {
        // Вывод всегда даёт тридцать два байта, и короткий ключ — это его
        // начало, а не отдельный вывод. Считать иначе значит получить другой
        // ключ и молчащее соединение.
        let salt = [7u8; SALT_LEN];
        let long = session_key("psk", &salt, Algorithm::ChaCha20Poly1305).expect("выводится");
        let short = session_key("psk", &salt, Algorithm::Aes128Gcm).expect("выводится");
        assert_eq!(&long[..16], &short[..]);
    }

    #[test]
    fn the_salt_and_the_password_both_change_the_key() {
        let a = session_key("psk", &[1u8; SALT_LEN], Algorithm::Aes128Gcm).expect("выводится");
        let b = session_key("psk", &[2u8; SALT_LEN], Algorithm::Aes128Gcm).expect("выводится");
        let c = session_key("другой", &[1u8; SALT_LEN], Algorithm::Aes128Gcm).expect("выводится");

        assert_ne!(a, b, "соль не участвует");
        assert_ne!(a, c, "пароль не участвует");
    }

    #[test]
    fn the_same_pair_gives_the_same_key() {
        // Иначе сервер и клиент разошлись бы на первом же куске.
        let salt = [3u8; SALT_LEN];
        assert_eq!(
            session_key("psk", &salt, Algorithm::Aes128Gcm).expect("выводится"),
            session_key("psk", &salt, Algorithm::Aes128Gcm).expect("выводится")
        );
    }

    #[test]
    fn the_parameters_are_the_ones_the_server_uses() {
        // Три прохода, восемь килобайт, один поток. Взяты у двух реализаций
        // и у разбора протокола; любое другое число даёт другой ключ.
        assert_eq!((PASSES, MEMORY_KIB, LANES), (3, 8, 1));
        assert_eq!(OUTPUT_LEN, 32);
        assert_eq!(SALT_LEN, 16);
    }

    #[test]
    fn a_salt_too_short_for_argon_is_an_error_and_not_a_panic() {
        // Argon2 требует не меньше восьми байт соли. Своя соль у нас всегда
        // нужной длины, а вот присланная — чужая.
        assert!(session_key("psk", &[0u8; 4], Algorithm::Aes128Gcm).is_err());
    }

    #[test]
    fn the_keying_hands_the_same_key_to_the_frame() {
        let salt = [5u8; SALT_LEN];
        let keying = keying("psk".to_owned(), Algorithm::Aes128Gcm);
        assert_eq!(
            keying.session_key(&salt).expect("выводится"),
            session_key("psk", &salt, Algorithm::Aes128Gcm).expect("выводится")
        );
        assert_eq!(keying.salt_len(), SALT_LEN);
    }
}
