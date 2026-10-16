//! Вывод ключей: из пароля — главный ключ, из главного и соли — сеансовый.
//!
//! ```text
//!  пароль ──EVP_BytesToKey──► главный ключ ──┐
//!                                            ├─HKDF-SHA1──► сеансовый ключ
//!  соль (случайная, на каждое соединение) ───┘
//! ```
//!
//! `EVP_BytesToKey` (MD5) — в [`penguin_transport::kdf`]; стойкость держится на длине
//! пароля. HKDF с солью нужен, чтобы пара «ключ, счётчик» не повторялась между
//! соединениями.

use std::sync::Arc;

use penguin_transport::aead::Keying;
use penguin_transport::error::TransportError;
use ring::hkdf;

use crate::crypto::method::Method;
use crate::error::{ShadowsocksError, ShadowsocksResult};

/// Метка вывода сеансового ключа; часть договора с сервером.
const INFO: &[u8] = b"ss-subkey";

/// Главный ключ из пароля — `EVP_BytesToKey` длиной под выбранный шифр.
pub fn master_key(password: &str, method: Method) -> Vec<u8> {
    penguin_transport::kdf::evp_bytes_to_key(password.as_bytes(), method.key_len())
}

/// Сеансовый ключ из главного и соли.
pub fn session_key(master: &[u8], salt: &[u8], method: Method) -> ShadowsocksResult<Vec<u8>> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt);
    let material = salt.extract(master);

    let length = KeyLen(method.key_len());
    let output = material
        .expand(&[INFO], length)
        .map_err(|_| ShadowsocksError::crypto("не выводится сеансовый ключ"))?;

    let mut key = vec![0u8; method.key_len()];
    output
        .fill(&mut key)
        .map_err(|_| ShadowsocksError::crypto("не выводится сеансовый ключ"))?;
    Ok(key)
}

/// Длина вывода для HKDF: `ring` требует её типом, а не числом.
#[derive(Debug, Clone, Copy)]
struct KeyLen(usize);

impl hkdf::KeyType for KeyLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Всё, что общему кадру нужно знать про ключи Shadowsocks.
pub fn keying(master: Vec<u8>, method: Method) -> Keying {
    Keying::new(
        method.algorithm(),
        method.salt_len(),
        Arc::new(move |salt: &[u8]| {
            session_key(&master, salt, method)
                .map_err(|err| TransportError::config(err.to_string()))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Шестнадцатеричная запись — только для сверки с чужими значениями.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn the_master_key_matches_the_known_answer() {
        // Пустой пароль: просто MD5 пустой строки
        let key = master_key("", Method::Aes128Gcm);
        assert_eq!(hex(&key), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn a_longer_key_continues_the_same_chain() {
        let short = master_key("пароль", Method::Aes128Gcm);
        let long = master_key("пароль", Method::Aes256Gcm);

        assert_eq!(short.len(), 16);
        assert_eq!(long.len(), 32);
        assert_eq!(&long[..16], &short[..]);
    }

    #[test]
    fn the_key_depends_on_the_password() {
        assert_ne!(
            master_key("один", Method::Aes256Gcm),
            master_key("два", Method::Aes256Gcm)
        );
    }

    #[test]
    fn the_session_key_changes_with_the_salt() {
        let master = master_key("пароль", Method::Aes256Gcm);
        let first = session_key(&master, &[1u8; 32], Method::Aes256Gcm).expect("выводится");
        let second = session_key(&master, &[2u8; 32], Method::Aes256Gcm).expect("выводится");

        assert_ne!(first, second);
        assert_eq!(first.len(), 32);
    }

    #[test]
    fn the_same_salt_gives_the_same_key() {
        let master = master_key("пароль", Method::Aes128Gcm);
        let salt = [7u8; 16];
        assert_eq!(
            session_key(&master, &salt, Method::Aes128Gcm).expect("выводится"),
            session_key(&master, &salt, Method::Aes128Gcm).expect("выводится")
        );
    }

    #[test]
    fn the_label_is_the_one_the_protocol_names() {
        // Вектора сеансового ключа нет: взять негде, свой вывод проверял бы сам себя
        assert_eq!(INFO, b"ss-subkey");
    }
}
