//! Чем шифруется тело: `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none`,
//! `zero` — и что из этого едет на провод.
//!
//! Числовые значения байта шифрования и раскладка битов настроек — из
//! `common/protocol/headers.pb.go` и `proxy/vmess/outbound/outbound.go`
//! эталона (`v2fly/v2ray-core`, ревизия `master` на момент чтения,
//! 2026-09-08): перечисление `SecurityType` (`AES128_GCM = 3`,
//! `CHACHA20_POLY1305 = 4`, `NONE = 5`, `ZERO = 6`) и то, какие биты
//! `RequestOption` выставляет клиент для каждого из них.

use md5::Digest as _;
use serde::{Deserialize, Serialize};

/// Шифр, как его выбирает человек в настройках.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cipher {
    /// AES-128-GCM, если ничего не сказано.
    ///
    /// Эталон выбирает между AES-128-GCM и ChaCha20-Poly1305 по тому, есть ли
    /// в процессоре аппаратный AES, — у нас `ring` быстр в обоих случаях, и
    /// выбирать по железу нечего: `auto` всегда означает AES-128-GCM.
    #[default]
    Auto,
    /// AES-128-GCM.
    Aes128Gcm,
    /// ChaCha20-Poly1305. Ключ перед использованием проходит два прохода
    /// MD5 — не наша прихоть, так делает сам протокол (см.
    /// [`Self::wire`] и [`crate::frame::body`]).
    Chacha20Poly1305,
    /// Без шифрования тела, но с тем же кадром: длина, метка (пустая),
    /// данные. Законно ровно тогда, когда TLS снаружи уже шифрует всё.
    None,
    /// Ни шифрования, ни кадра. Опаснее, чем `none`: там хотя бы сохраняются
    /// границы кусков, здесь исчезают и они. Форма обязана предупреждать
    /// (`AGENTS.md` §5.3 — тот же принцип, что и для отключённой проверки
    /// сертификата).
    Zero,
}

/// Шифр, уже приведённый к тому, что реально едет на провод — `auto` в этот
/// момент не бывает.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// Байт `3`.
    Aes128Gcm,
    /// Байт `4`.
    Chacha20Poly1305,
    /// Байт `5`, кадр остаётся.
    None,
    /// Байт `5` — сервер видит то же, что при `None`; разница только в
    /// битах настроек ([`Wire::option_byte`]) и в теле, у которого кадра нет
    /// вовсе.
    Zero,
}

impl Cipher {
    /// Приводит `auto` к конкретному шифру. Дальше по коду `auto` не ходит.
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

    /// Биты настроек (`RequestOption`), которые клиент выставляет для этого
    /// шифра по умолчанию — в форме их не выбирают, это не пользовательская
    /// настройка, а часть протокола.
    ///
    /// `0x01` кадры, `0x04` маскировка длин, `0x08` общее дополнение.
    /// `0x02` (переиспользование соединения) и `0x10` (заверенная длина) не
    /// выставляются никогда: первое устарело у самого эталона, второе —
    /// экспериментальный флаг, выключенный там по умолчанию.
    pub fn option_byte(self) -> u8 {
        match self {
            Self::Aes128Gcm | Self::Chacha20Poly1305 => 0x01 | 0x04 | 0x08,
            Self::None => 0x01 | 0x04,
            Self::Zero => 0x00,
        }
    }

    /// Есть ли у тела кадр (длина + кусок) вообще.
    ///
    /// Только `zero` идёт голым потоком без единой границы — то, что делает
    /// его опаснее `none`.
    pub fn is_framed(self) -> bool {
        !matches!(self, Self::Zero)
    }

    /// Длина метки подлинности AEAD. Ноль — не значит небезопасно само по
    /// себе: у `none` кадр всё равно есть, метки в нём просто нет.
    pub fn tag_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Chacha20Poly1305 => 16,
            Self::None | Self::Zero => 0,
        }
    }

    /// Ключ тела, приведённый к тому, что действительно уходит в AEAD.
    ///
    /// У ChaCha20-Poly1305 шестнадцатибайтовый ключ тела не берётся как
    /// есть: эталон растягивает его до тридцати двух байт двумя проходами
    /// MD5 — `key[..16] = MD5(body_key)`, `key[16..] = MD5(key[..16])`
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

    /// Алгоритм `ring`, если он вообще есть у этого шифра.
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
        // `zero` не заводит отдельного значения байта — сервер видит `none`.
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
        // Маскировка длины есть, общего дополнения нет: `shouldEnablePadding`
        // у эталона требует либо AES-128-GCM/ChaCha, либо отдельный флаг,
        // включённый по умолчанию выключенным.
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
