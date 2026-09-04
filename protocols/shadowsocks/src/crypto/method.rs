//! Метод шифрования: какой шифр и какой длины у него ключ.
//!
//! Три метода, и все три — AEAD, то есть данные не только шифруются, но и
//! заверяются: изменить их по дороге незаметно нельзя.
//!
//! Потоковых шифров прежних версий (`aes-256-cfb`, `rc4-md5`) здесь нет
//! намеренно. Они не заверяют данные вовсе: тот, кто видит трафик, может
//! править его как угодно, и ни клиент, ни сервер этого не заметят. Метод,
//! который выглядит как «просто ещё один в списке», а на деле снимает защиту
//! целиком, в списке стоять не должен.

use ring::aead;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{ShadowsocksError, ShadowsocksResult};

/// Длина метки подлинности у всех трёх методов.
pub const TAG_LEN: usize = 16;

/// Метод шифрования.
///
/// `serde` здесь написан вручную поверх [`Method::parse`], а не выведен.
/// Производный принял бы ровно одно написание на вариант, а в чужих
/// настройках их два: `chacha20-poly1305` и `chacha20-ietf-poly1305` — это
/// один и тот же метод. И текст ошибки был бы про «неизвестный вариант
/// перечисления», а не про неизвестный метод шифрования.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// AES-128-GCM. Быстрее всех там, где у процессора есть AES-NI.
    Aes128Gcm,
    /// AES-256-GCM. Ключ вдвое длиннее, скорость та же.
    Aes256Gcm,
    /// ChaCha20-Poly1305. Быстрее AES там, где AES-NI нет, — на телефонах и
    /// маломощных маршрутизаторах.
    Chacha20Poly1305,
}

impl Serialize for Method {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self.name())
    }
}

impl<'de> Deserialize<'de> for Method {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let name = String::deserialize(de)?;
        Self::parse(&name).map_err(serde::de::Error::custom)
    }
}

impl Method {
    /// Разбирает имя метода так, как его пишут в настройках и ссылках.
    pub fn parse(name: &str) -> ShadowsocksResult<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            // Второе имя того же метода: так его зовут старые конфигурации.
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(Self::Chacha20Poly1305),
            other => Err(ShadowsocksError::UnknownMethod(other.to_owned())),
        }
    }

    /// Имя метода в настройках.
    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Chacha20Poly1305 => "chacha20-ietf-poly1305",
        }
    }

    /// Длина ключа в байтах.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::Chacha20Poly1305 => 32,
        }
    }

    /// Длина соли.
    ///
    /// Совпадает с длиной ключа — так задано протоколом, а не выведено из
    /// удобства.
    pub fn salt_len(self) -> usize {
        self.key_len()
    }

    /// Шифр в терминах `ring`.
    pub fn algorithm(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128Gcm => &aead::AES_128_GCM,
            Self::Aes256Gcm => &aead::AES_256_GCM,
            Self::Chacha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_method_round_trips_through_its_name() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            assert_eq!(Method::parse(method.name()).expect("разбирается"), method);
        }
    }

    #[test]
    fn the_older_spelling_is_understood() {
        // Так метод зовут старые конфигурации; это тот же самый метод.
        assert_eq!(
            Method::parse("chacha20-poly1305").expect("разбирается"),
            Method::Chacha20Poly1305
        );
    }

    #[test]
    fn the_name_is_case_insensitive() {
        assert_eq!(
            Method::parse("AES-256-GCM").expect("разбирается"),
            Method::Aes256Gcm
        );
    }

    #[test]
    fn an_unknown_method_names_itself_in_the_error() {
        // «Неверные настройки» без имени метода не отвечают на вопрос, что
        // именно исправить.
        let err = Method::parse("rc4-md5").expect_err("такого метода нет");
        assert!(err.to_string().contains("rc4-md5"), "{err}");
    }

    #[test]
    fn a_stream_cipher_is_not_silently_accepted() {
        // Потоковые шифры не заверяют данные: правку по дороге не заметит ни
        // клиент, ни сервер. Принять их молча значит снять защиту целиком.
        for name in ["aes-256-cfb", "rc4-md5", "chacha20"] {
            assert!(Method::parse(name).is_err(), "{name}");
        }
    }

    #[test]
    fn the_salt_is_as_long_as_the_key() {
        // Так задано протоколом: соль короче ключа сервер не примет.
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            assert_eq!(method.salt_len(), method.key_len());
            assert_eq!(method.key_len(), method.algorithm().key_len());
        }
    }

    #[test]
    fn the_tag_is_the_same_length_everywhere() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            assert_eq!(method.algorithm().tag_len(), TAG_LEN);
        }
    }
}
