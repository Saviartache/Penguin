//! Какие шифры бывают и какой длины у них ключ.

use ring::aead;

/// Длина метки подлинности. У всех трёх алгоритмов она одна.
pub const TAG_LEN: usize = 16;

/// Длина нонса. Тоже одна у всех трёх.
pub const NONCE_LEN: usize = 12;

/// Шифр, которым закрывается кусок.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// AES-128 в режиме GCM. Ключ шестнадцать байт.
    Aes128Gcm,
    /// AES-256 в режиме GCM. Ключ тридцать два байта.
    Aes256Gcm,
    /// ChaCha20 с Poly1305. Ключ тридцать два байта.
    ChaCha20Poly1305,
}

impl Algorithm {
    /// Длина ключа в байтах.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    /// Как этот шифр называется у `ring`.
    pub fn ring(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128Gcm => &aead::AES_128_GCM,
            Self::Aes256Gcm => &aead::AES_256_GCM,
            Self::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }

    /// Имя, под которым шифр стоит в настройках.
    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_length_matches_the_one_ring_wants() {
        // Разойтись им нельзя: `ring` откажется собрать ключ, и протокол
        // объявит это ошибкой настроек там, где ошибка в таблице.
        for algorithm in [
            Algorithm::Aes128Gcm,
            Algorithm::Aes256Gcm,
            Algorithm::ChaCha20Poly1305,
        ] {
            assert_eq!(
                algorithm.key_len(),
                algorithm.ring().key_len(),
                "{}",
                algorithm.name()
            );
        }
    }

    #[test]
    fn the_tag_and_the_nonce_are_the_same_for_all_of_them() {
        for algorithm in [
            Algorithm::Aes128Gcm,
            Algorithm::Aes256Gcm,
            Algorithm::ChaCha20Poly1305,
        ] {
            assert_eq!(algorithm.ring().tag_len(), TAG_LEN);
            assert_eq!(algorithm.ring().nonce_len(), NONCE_LEN);
        }
    }
}
