//! Метод шифрования: шифр и длина ключа. Только AEAD; потоковых шифров нет намеренно:
//! они не заверяют данные.

use penguin_transport::aead::Algorithm;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{ShadowsocksError, ShadowsocksResult};

/// Длина метки подлинности (из общего слоя).
pub const TAG_LEN: usize = penguin_transport::aead::TAG_LEN;

/// Метод шифрования; `serde` поверх [`Method::parse`] принимает оба написания ChaCha.
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

    /// Длина соли; равна длине ключа по протоколу.
    pub fn salt_len(self) -> usize {
        self.key_len()
    }

    /// Шифр в терминах общего слоя.
    pub fn algorithm(self) -> Algorithm {
        match self {
            Self::Aes128Gcm => Algorithm::Aes128Gcm,
            Self::Aes256Gcm => Algorithm::Aes256Gcm,
            Self::Chacha20Poly1305 => Algorithm::ChaCha20Poly1305,
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
        let err = Method::parse("rc4-md5").expect_err("такого метода нет");
        assert!(err.to_string().contains("rc4-md5"), "{err}");
    }

    #[test]
    fn a_stream_cipher_is_not_silently_accepted() {
        for name in ["aes-256-cfb", "rc4-md5", "chacha20"] {
            assert!(Method::parse(name).is_err(), "{name}");
        }
    }

    #[test]
    fn the_salt_is_as_long_as_the_key() {
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
    fn the_key_length_matches_the_shared_table() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            assert_eq!(
                method.key_len(),
                method.algorithm().key_len(),
                "{}",
                method.name()
            );
        }
    }
}
