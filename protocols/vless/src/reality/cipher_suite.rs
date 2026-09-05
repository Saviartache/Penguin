//! Три шифра TLS 1.3, из которых сервер выбирает один в `ServerHello` —
//! RFC 8446 §B.4.
//!
//! Reality не вводит своих шифров: набор ровно тот, что предлагает
//! `ClientHello` любого из трёх отпечатков `penguin-utls` (`0x1301`, `0x1302`,
//! `0x1303`, каждый в своём порядке). Отсюда и хеш транскрипта — он не
//! настраивается отдельно, а вытекает из выбранного шифра (RFC 8446 §7.1).

use ring::aead;
use ring::hkdf;

/// Один из трёх шифров TLS 1.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// `TLS_AES_128_GCM_SHA256` (`0x1301`).
    Aes128GcmSha256,
    /// `TLS_AES_256_GCM_SHA384` (`0x1302`).
    Aes256GcmSha384,
    /// `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`).
    Chacha20Poly1305Sha256,
}

impl CipherSuite {
    /// Разбирает код шифра из `ServerHello`. `None` — сервер выбрал что-то за
    /// пределами TLS 1.3, чего эта реализация не ведёт.
    pub fn from_u16(code: u16) -> Option<Self> {
        match code {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    /// Алгоритм хеша транскрипта и `HKDF` этого шифра (RFC 8446 §7.1).
    pub fn hkdf_algorithm(self) -> hkdf::Algorithm {
        match self {
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => hkdf::HKDF_SHA256,
            Self::Aes256GcmSha384 => hkdf::HKDF_SHA384,
        }
    }

    /// Тот же хеш, но для отдельного вычисления хеша транскрипта — `HKDF`
    /// `ring` не даёт хешировать в одиночку, только вывод ключей.
    pub fn digest_algorithm(self) -> &'static ring::digest::Algorithm {
        match self {
            Self::Aes128GcmSha256 | Self::Chacha20Poly1305Sha256 => &ring::digest::SHA256,
            Self::Aes256GcmSha384 => &ring::digest::SHA384,
        }
    }

    /// Длина хеша транскрипта и секретов ключевого расписания — 32 байта для
    /// SHA-256, 48 для SHA-384.
    pub fn hash_len(self) -> usize {
        self.digest_algorithm().output_len()
    }

    /// AEAD, которым шифрует эту запись.
    pub fn aead_algorithm(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128GcmSha256 => &aead::AES_128_GCM,
            Self::Aes256GcmSha384 => &aead::AES_256_GCM,
            Self::Chacha20Poly1305Sha256 => &aead::CHACHA20_POLY1305,
        }
    }

    /// Длина ключа AEAD: 16 байт для `AES-128-GCM`, 32 — для двух остальных.
    pub fn key_len(self) -> usize {
        self.aead_algorithm().key_len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_tls13_codes_are_recognized() {
        assert_eq!(
            CipherSuite::from_u16(0x1301),
            Some(CipherSuite::Aes128GcmSha256)
        );
        assert_eq!(
            CipherSuite::from_u16(0x1302),
            Some(CipherSuite::Aes256GcmSha384)
        );
        assert_eq!(
            CipherSuite::from_u16(0x1303),
            Some(CipherSuite::Chacha20Poly1305Sha256)
        );
    }

    #[test]
    fn anything_outside_tls13_is_rejected() {
        // 0xc02b — TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (TLS 1.2): Reality
        // требует TLS 1.3, и сервер, согласившийся на меньшее, не наш случай.
        assert_eq!(CipherSuite::from_u16(0xc02b), None);
    }

    #[test]
    fn aes_256_is_the_only_one_with_sha384() {
        assert_eq!(CipherSuite::Aes128GcmSha256.hash_len(), 32);
        assert_eq!(CipherSuite::Chacha20Poly1305Sha256.hash_len(), 32);
        assert_eq!(CipherSuite::Aes256GcmSha384.hash_len(), 48);
    }

    #[test]
    fn only_aes_128_has_a_sixteen_byte_key() {
        assert_eq!(CipherSuite::Aes128GcmSha256.key_len(), 16);
        assert_eq!(CipherSuite::Aes256GcmSha384.key_len(), 32);
        assert_eq!(CipherSuite::Chacha20Poly1305Sha256.key_len(), 32);
    }
}
