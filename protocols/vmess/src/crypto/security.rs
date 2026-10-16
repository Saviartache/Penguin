//! Шифр тела и то, что из него едет на провод.
//!
//! Байты шифра и биты настроек: `common/protocol/headers.pb.go` (`SecurityType`:
//! `AES128_GCM = 3`, `CHACHA20_POLY1305 = 4`, `NONE = 5`, `ZERO = 6`) и
//! `proxy/vmess/outbound/outbound.go`, `v2fly/v2ray-core`.

use md5::Digest as _;
use serde::{Deserialize, Serialize};

/// Шифр, как его выбирает человек в настройках.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cipher {
    /// AES-128-GCM; `ring` быстр на любом железе, выбирать по нему нечего.
    #[default]
    Auto,
    /// AES-128-GCM.
    Aes128Gcm,
    /// ChaCha20-Poly1305; ключ по протоколу проходит два прохода MD5.
    Chacha20Poly1305,
    /// Без шифрования, но с кадром; законно, только если TLS снаружи.
    None,
    /// Ни шифрования, ни кадра: исчезают и границы кусков. Форма обязана предупреждать (§5.3).
    Zero,
}

/// Шифр, приведённый к проводу (без `auto`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// Байт `3`.
    Aes128Gcm,
    /// Байт `4`.
    Chacha20Poly1305,
    /// Байт `5`, кадр остаётся.
    None,
    /// Байт `5`, как у `None`; отличаются биты настроек и отсутствие кадра.
    Zero,
}

impl Cipher {
    /// Приводит `auto` к конкретному шифру.
    pub fn wire(self) -> Wire {
        match self {
            Self::Auto | Self::Aes128Gcm => Wire::Aes128Gcm,
            Self::Chacha20Poly1305 => Wire::Chacha20Poly1305,
            Self::None => Wire::None,
            Self::Zero => Wire::Zero,
        }
    }
}

impl Wire {
    /// Байт шифра в заголовке (младшие четыре бита байта `security`).
    pub fn security_byte(self) -> u8 {
        match self {
            Self::Aes128Gcm => 3,
            Self::Chacha20Poly1305 => 4,
            Self::None | Self::Zero => 5,
        }
    }

    /// Биты `RequestOption`: `0x01` кадры, `0x04` маскировка длин, `0x08` дополнение.
    /// `0x02` и `0x10` не выставляются: устарел и экспериментален у эталона.
    pub fn option_byte(self) -> u8 {
        match self {
            Self::Aes128Gcm | Self::Chacha20Poly1305 => 0x01 | 0x04 | 0x08,
            Self::None => 0x01 | 0x04,
            Self::Zero => 0x00,
        }
    }

    /// Есть ли у тела кадр; без него только `zero`.
    pub fn is_framed(self) -> bool {
        !matches!(self, Self::Zero)
    }

    /// Длина метки AEAD; у `none` кадр есть, метки нет.
    pub fn tag_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Chacha20Poly1305 => 16,
            Self::None | Self::Zero => 0,
        }
    }

    /// Ключ для AEAD. У ChaCha20-Poly1305: `MD5(key) || MD5(MD5(key))`
    /// (`GenerateChacha20Poly1305Key`, `proxy/vmess/encoding/auth.go`).
    pub fn effective_key(self, body_key: &[u8; 16]) -> Vec<u8> {
        match self {
            Self::Aes128Gcm => body_key.to_vec(),
            Self::Chacha20Poly1305 => {
                let first: [u8; 16] = md5::Md5::digest(body_key).into();
                let second: [u8; 16] = md5::Md5::digest(first).into();
                let mut key = Vec::with_capacity(32);
                key.extend_from_slice(&first);
                key.extend_from_slice(&second);
                key
            }
            Self::None | Self::Zero => Vec::new(),
        }
    }

    /// Алгоритм `ring`, если есть.
    pub fn ring_algorithm(self) -> Option<&'static ring::aead::Algorithm> {
        match self {
            Self::Aes128Gcm => Some(&ring::aead::AES_128_GCM),
            Self::Chacha20Poly1305 => Some(&ring::aead::CHACHA20_POLY1305),
            Self::None | Self::Zero => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_becomes_aes_128_gcm() {
        assert_eq!(Cipher::Auto.wire(), Wire::Aes128Gcm);
    }

    #[test]
    fn wire_bytes_match_the_reference_enum() {
        assert_eq!(Wire::Aes128Gcm.security_byte(), 3);
        assert_eq!(Wire::Chacha20Poly1305.security_byte(), 4);
        assert_eq!(Wire::None.security_byte(), 5);
        assert_eq!(Wire::Zero.security_byte(), 5);
    }

    #[test]
    fn only_zero_has_no_frame() {
        assert!(Wire::Aes128Gcm.is_framed());
        assert!(Wire::Chacha20Poly1305.is_framed());
        assert!(Wire::None.is_framed());
        assert!(!Wire::Zero.is_framed());
    }

    #[test]
    fn zero_clears_every_option_bit() {
        assert_eq!(Wire::Zero.option_byte(), 0x00);
    }

    #[test]
    fn none_is_framed_but_not_padded() {
        assert_eq!(Wire::None.option_byte(), 0x01 | 0x04);
    }

    #[test]
    fn chacha_key_is_stretched_by_double_md5() {
        let body_key = [7u8; 16];
        let key = Wire::Chacha20Poly1305.effective_key(&body_key);
        assert_eq!(key.len(), 32);

        let first: [u8; 16] = md5::Md5::digest(body_key).into();
        assert_eq!(&key[..16], &first);
        let second: [u8; 16] = md5::Md5::digest(first).into();
        assert_eq!(&key[16..], &second);
    }

    #[test]
    fn aes_key_is_used_as_is() {
        let body_key = [9u8; 16];
        assert_eq!(Wire::Aes128Gcm.effective_key(&body_key), body_key.to_vec());
    }
}
