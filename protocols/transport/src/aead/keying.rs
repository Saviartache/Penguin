//! Как из соли получается сеансовый ключ.
//!
//! Это единственное, чем протоколы с одинаковым обрамлением различаются между
//! собой. У Shadowsocks ключ выводит HKDF-SHA1 из главного ключа, у Snell —
//! Argon2id прямо из пароля. Кадр при этом один и тот же, и держать из-за
//! разного вывода два кадра было бы дороже, чем передать вывод сюда.
//!
//! Соль каждый раз новая и уходит открытым текстом первой. Смысл её в том,
//! что ключ на каждое соединение свой: повторить пару «ключ, счётчик» для
//! AEAD значит раскрыть оба сообщения.

use std::sync::Arc;

use crate::aead::algorithm::Algorithm;
use crate::aead::cipher::Cipher;
use crate::error::{TransportError, TransportResult};

/// Как протокол выводит сеансовый ключ из соли.
pub type Derive = Arc<dyn Fn(&[u8]) -> TransportResult<Vec<u8>> + Send + Sync>;

/// Шифр, длина соли и вывод ключа — всё, что нужно потоку.
#[derive(Clone)]
pub struct Keying {
    algorithm: Algorithm,
    salt_len: usize,
    derive: Derive,
}

impl std::fmt::Debug for Keying {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keying")
            .field("algorithm", &self.algorithm.name())
            .field("salt_len", &self.salt_len)
            .finish()
    }
}

impl Keying {
    /// Собирает описание. `derive` зовётся один раз на каждое направление.
    pub fn new(algorithm: Algorithm, salt_len: usize, derive: Derive) -> Self {
        Self {
            algorithm,
            salt_len,
            derive,
        }
    }

    /// Каким шифром закрываются куски.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Сколько байт занимает соль на проводе.
    pub fn salt_len(&self) -> usize {
        self.salt_len
    }

    /// Выводит сеансовый ключ.
    ///
    /// `Err` — вывод дал ключ не той длины. Это ошибка не человека, а
    /// протокола: длина ключа задана шифром, и разойтись им нельзя.
    pub fn session_key(&self, salt: &[u8]) -> TransportResult<Vec<u8>> {
        let key = (self.derive)(salt)?;
        if key.len() != self.algorithm.key_len() {
            return Err(TransportError::config(format!(
                "вывод ключа дал {} байт вместо {} для {}",
                key.len(),
                self.algorithm.key_len(),
                self.algorithm.name()
            )));
        }
        Ok(key)
    }

    /// Готовый шифр под эту соль.
    pub fn cipher(&self, salt: &[u8]) -> TransportResult<Cipher> {
        Cipher::new(self.algorithm, &self.session_key(salt)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keying(algorithm: Algorithm, key_len: usize) -> Keying {
        Keying::new(
            algorithm,
            16,
            Arc::new(move |salt: &[u8]| Ok(vec![salt.first().copied().unwrap_or(0); key_len])),
        )
    }

    #[test]
    fn the_key_comes_from_the_salt() {
        let keying = keying(Algorithm::Aes128Gcm, 16);
        assert_eq!(keying.session_key(&[7; 16]).expect("выводится"), [7u8; 16]);
        assert_ne!(
            keying.session_key(&[7; 16]).expect("выводится"),
            keying.session_key(&[9; 16]).expect("выводится"),
            "соль не влияет на ключ"
        );
    }

    #[test]
    fn a_key_of_the_wrong_length_is_caught_here_and_not_inside_the_cipher() {
        // Иначе ошибка вывода выглядела бы ошибкой ключа, и искали бы её в
        // пароле, а не в таблице длин.
        let keying = keying(Algorithm::Aes256Gcm, 16);
        let err = keying.session_key(&[1; 16]).expect_err("длина не та");
        assert!(err.to_string().contains("16 байт вместо 32"), "{err}");
    }

    #[test]
    fn a_derivation_that_fails_is_passed_up() {
        let keying = Keying::new(
            Algorithm::Aes128Gcm,
            16,
            Arc::new(|_| Err(TransportError::config("нечем выводить"))),
        );
        assert!(keying.cipher(&[0; 16]).is_err());
    }
}
