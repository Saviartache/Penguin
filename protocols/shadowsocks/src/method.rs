//! Метод шифрования Shadowsocks: обычный AEAD или AEAD 2022.
//!
//! Список имён — из шести, а не из трёх: [`crate::crypto::Method`] остаётся
//! рабочей частью AEAD, которую эта фаза не трогает, а три метода
//! `2022-blake3-*` — [`Method2022`], с другим выводом ключа ([`crate::kdf2022`])
//! и другим заголовком ([`crate::tcp2022`], [`crate::udp2022`]). Этот файл
//! только выбирает между ними по имени; крипто-логики здесь нет.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::Method;
use crate::error::ShadowsocksResult;

/// Метод Shadowsocks 2022.
///
/// Тот же список шифров, что у AEAD, но ключ — не пароль, а закодированный
/// в base64 предварительный общий ключ (PSK) ровно нужной длины, и вывод
/// сеансового ключа — BLAKE3, а не HKDF-SHA1 (см. [`crate::kdf2022`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method2022 {
    /// `2022-blake3-aes-128-gcm`. Ключ 16 байт.
    Blake3Aes128Gcm,
    /// `2022-blake3-aes-256-gcm`. Ключ 32 байта.
    Blake3Aes256Gcm,
    /// `2022-blake3-chacha20-poly1305`. Ключ 32 байта.
    Blake3Chacha20Poly1305,
}

impl Method2022 {
    /// Разбирает имя метода 2022. `None` — это не метод 2022 (возможно,
    /// обычный AEAD, а возможно, ошибка — решает вызывающий).
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "2022-blake3-aes-128-gcm" => Some(Self::Blake3Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Some(Self::Blake3Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Some(Self::Blake3Chacha20Poly1305),
            _ => None,
        }
    }

    /// Имя метода в настройках и ссылках.
    pub fn name(self) -> &'static str {
        match self {
            Self::Blake3Aes128Gcm => "2022-blake3-aes-128-gcm",
            Self::Blake3Aes256Gcm => "2022-blake3-aes-256-gcm",
            Self::Blake3Chacha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }

    /// Длина ключа (PSK) в байтах.
    pub fn key_len(self) -> usize {
        match self {
            Self::Blake3Aes128Gcm => 16,
            Self::Blake3Aes256Gcm | Self::Blake3Chacha20Poly1305 => 32,
        }
    }

    /// Длина соли TCP.
    ///
    /// Совпадает с длиной ключа — так задано протоколом
    /// (`shadowsocks-crypto`, `kind.rs::salt_len`), а не выведено из
    /// удобства (тот же приём, что у обычного AEAD).
    pub fn salt_len(self) -> usize {
        self.key_len()
    }

    /// Использует ли метод AES-GCM (а не ChaCha).
    ///
    /// От этого зависит устройство UDP: у AES-GCM заголовок с
    /// идентификатором сессии шифруется отдельно голым AES, у ChaCha —
    /// нонс просто 24 случайных байта перед пакетом (`udp2022::cipher`).
    pub fn is_aes_gcm(self) -> bool {
        matches!(self, Self::Blake3Aes128Gcm | Self::Blake3Aes256Gcm)
    }

    /// Шифр TCP-потока в терминах общего слоя.
    ///
    /// Только для TCP: там ChaCha20-Poly1305 обычный, с растущим 12-байтовым
    /// нонсом, — общий слой (`penguin_transport::aead`) это умеет. У UDP
    /// ChaCha — это `XChaCha20`, с явным 24-байтовым нонсом на пакет, и там
    /// нужны свои разовые операции (`crate::udp2022::cipher`).
    pub fn algorithm(self) -> penguin_transport::aead::Algorithm {
        use penguin_transport::aead::Algorithm;
        match self {
            Self::Blake3Aes128Gcm => Algorithm::Aes128Gcm,
            Self::Blake3Aes256Gcm => Algorithm::Aes256Gcm,
            Self::Blake3Chacha20Poly1305 => Algorithm::ChaCha20Poly1305,
        }
    }
}

/// Метод шифрования Shadowsocks: обычный AEAD или AEAD 2022.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowsocksMethod {
    /// Обычный AEAD: пароль, `EVP_BytesToKey`, HKDF-SHA1.
    Aead(Method),
    /// Shadowsocks 2022: PSK в base64, BLAKE3.
    Aead2022(Method2022),
}

impl ShadowsocksMethod {
    /// Разбирает имя метода — любое из шести.
    pub fn parse(name: &str) -> ShadowsocksResult<Self> {
        // 2022 проверяется первым: имена не пересекаются, но так порядок
        // проверки не зависит от того, в каком списке заведут седьмой метод.
        if let Some(method) = Method2022::parse(name) {
            return Ok(Self::Aead2022(method));
        }
        Method::parse(name).map(Self::Aead)
    }

    /// Имя метода в настройках и ссылках.
    pub fn name(self) -> &'static str {
        match self {
            Self::Aead(method) => method.name(),
            Self::Aead2022(method) => method.name(),
        }
    }
}

impl Serialize for ShadowsocksMethod {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self.name())
    }
}

impl<'de> Deserialize<'de> for ShadowsocksMethod {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let name = String::deserialize(de)?;
        Self::parse(&name).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_2022: [Method2022; 3] = [
        Method2022::Blake3Aes128Gcm,
        Method2022::Blake3Aes256Gcm,
        Method2022::Blake3Chacha20Poly1305,
    ];

    #[test]
    fn every_2022_method_round_trips_through_its_name() {
        for method in ALL_2022 {
            assert_eq!(Method2022::parse(method.name()), Some(method));
        }
    }

    #[test]
    fn the_key_length_matches_the_documented_table() {
        assert_eq!(Method2022::Blake3Aes128Gcm.key_len(), 16);
        assert_eq!(Method2022::Blake3Aes256Gcm.key_len(), 32);
        assert_eq!(Method2022::Blake3Chacha20Poly1305.key_len(), 32);
    }

    #[test]
    fn the_salt_is_as_long_as_the_key() {
        for method in ALL_2022 {
            assert_eq!(method.salt_len(), method.key_len());
        }
    }

    #[test]
    fn the_tcp_algorithm_key_length_matches_the_method_key_length() {
        // Разойтись им нельзя: подключ выводит этот файл, а собирает общий
        // слой, и лишний байт означал бы «ключ не той длины» на ровном месте.
        for method in ALL_2022 {
            assert_eq!(
                method.algorithm().key_len(),
                method.key_len(),
                "{}",
                method.name()
            );
        }
    }

    #[test]
    fn only_the_aes_variants_report_aes_gcm() {
        assert!(Method2022::Blake3Aes128Gcm.is_aes_gcm());
        assert!(Method2022::Blake3Aes256Gcm.is_aes_gcm());
        assert!(!Method2022::Blake3Chacha20Poly1305.is_aes_gcm());
    }

    #[test]
    fn a_plain_aead_name_still_resolves() {
        assert_eq!(
            ShadowsocksMethod::parse("aes-256-gcm").expect("разбирается"),
            ShadowsocksMethod::Aead(Method::Aes256Gcm)
        );
    }

    #[test]
    fn a_2022_name_resolves_to_the_2022_variant() {
        assert_eq!(
            ShadowsocksMethod::parse("2022-blake3-chacha20-poly1305").expect("разбирается"),
            ShadowsocksMethod::Aead2022(Method2022::Blake3Chacha20Poly1305)
        );
    }

    #[test]
    fn an_unknown_name_names_itself_in_the_error() {
        let err = ShadowsocksMethod::parse("rc4-md5").expect_err("такого метода нет");
        assert!(err.to_string().contains("rc4-md5"), "{err}");
    }

    #[test]
    fn every_method_round_trips_through_serde() {
        for method in ALL_2022 {
            let wrapped = ShadowsocksMethod::Aead2022(method);
            let json = serde_json::to_string(&wrapped).expect("сериализуется");
            let back: ShadowsocksMethod = serde_json::from_str(&json).expect("разбирается");
            assert_eq!(back, wrapped);
        }
    }
}
