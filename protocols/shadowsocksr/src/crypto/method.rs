//! Метод шифрования: какой шифр, какой длины ключ и IV.
//!
//! Таблица длин переписана из `shadowsocks/crypto/openssl.py` и
//! `shadowsocks/crypto/rc4_md5.py` эталонной реализации (ветка `manyuser`,
//! репозиторий `shadowsocksr-backup/shadowsocksr`) — так вычисляет их
//! сервер, и разойтись с ним нельзя.
//!
//! Список здесь короче, чем в оригинале: он поддерживал ещё `bf-cfb`,
//! `camellia-*-cfb`, `cast5-cfb`, `des-cfb`, `idea-cfb`, `rc2-cfb`,
//! `seed-cfb`, `salsa20`, `chacha20` и вариации `cfb1`/`cfb8`/`ofb`. Это
//! редкие и по большей части устаревшие шифры; добавить их можно позже точно
//! так же, одной строкой в таблицу и одним вариантом в
//! [`crate::crypto::cipher`]. Заявить в `validate()` неизвестный метод лучше,
//! чем угадать шифр молча.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{ShadowsocksrError, ShadowsocksrResult};

/// Метод потокового шифрования.
///
/// **Ни один из них не заверяет данные.** Это не пропуск в реализации, а
/// свойство самого протокола — подробности в документе крейта
/// ([`crate`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Без шифрования вовсе. Соединение защищено только надстройками obfs и
    /// protocol, если они включены — сам по себе метод не прячет ничего.
    None,
    /// RC4 с ключом, размешанным по MD5 по паролю и IV. Исторический метод
    /// по умолчанию у SSR; RC4 сам по себе давно не считается стойким.
    Rc4Md5,
    /// AES-128 в режиме CFB.
    Aes128Cfb,
    /// AES-192 в режиме CFB.
    Aes192Cfb,
    /// AES-256 в режиме CFB.
    Aes256Cfb,
    /// AES-128 в режиме CTR.
    Aes128Ctr,
    /// AES-192 в режиме CTR.
    Aes192Ctr,
    /// AES-256 в режиме CTR.
    Aes256Ctr,
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
    /// Разбирает имя метода так, как его пишут в ссылках `ssr://`.
    pub fn parse(name: &str) -> ShadowsocksrResult<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "rc4-md5" => Ok(Self::Rc4Md5),
            "aes-128-cfb" => Ok(Self::Aes128Cfb),
            "aes-192-cfb" => Ok(Self::Aes192Cfb),
            "aes-256-cfb" => Ok(Self::Aes256Cfb),
            "aes-128-ctr" => Ok(Self::Aes128Ctr),
            "aes-192-ctr" => Ok(Self::Aes192Ctr),
            "aes-256-ctr" => Ok(Self::Aes256Ctr),
            other => Err(ShadowsocksrError::UnknownMethod(other.to_owned())),
        }
    }

    /// Имя метода в настройках.
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Rc4Md5 => "rc4-md5",
            Self::Aes128Cfb => "aes-128-cfb",
            Self::Aes192Cfb => "aes-192-cfb",
            Self::Aes256Cfb => "aes-256-cfb",
            Self::Aes128Ctr => "aes-128-ctr",
            Self::Aes192Ctr => "aes-192-ctr",
            Self::Aes256Ctr => "aes-256-ctr",
        }
    }

    /// Длина главного ключа в байтах — второй параметр `EVP_BytesToKey`.
    pub fn key_len(self) -> usize {
        match self {
            Self::None => 16,
            Self::Rc4Md5 => 16,
            Self::Aes128Cfb | Self::Aes128Ctr => 16,
            Self::Aes192Cfb | Self::Aes192Ctr => 24,
            Self::Aes256Cfb | Self::Aes256Ctr => 32,
        }
    }

    /// Длина IV в байтах — третий параметр `EVP_BytesToKey`, он же длина
    /// заголовка, который уходит в открытую перед первым куском.
    pub fn iv_len(self) -> usize {
        match self {
            Self::None => 0,
            _ => 16,
        }
    }

    /// Настоящее шифрование, а не заглушка `none`.
    pub fn encrypts(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Method; 8] = [
        Method::None,
        Method::Rc4Md5,
        Method::Aes128Cfb,
        Method::Aes192Cfb,
        Method::Aes256Cfb,
        Method::Aes128Ctr,
        Method::Aes192Ctr,
        Method::Aes256Ctr,
    ];

    #[test]
    fn every_method_round_trips_through_its_name() {
        for method in ALL {
            assert_eq!(Method::parse(method.name()).expect("разбирается"), method);
        }
    }

    #[test]
    fn the_name_is_case_insensitive() {
        assert_eq!(
            Method::parse("AES-256-CFB").expect("разбирается"),
            Method::Aes256Cfb
        );
    }

    #[test]
    fn an_unknown_method_names_itself_in_the_error() {
        let err = Method::parse("idea-cfb").expect_err("не реализован в этой версии");
        assert!(err.to_string().contains("idea-cfb"), "{err}");
    }

    #[test]
    fn key_lengths_match_the_reference_table() {
        // Таблица из `shadowsocks/crypto/openssl.py`: разойтись с сервером
        // здесь значит получить другой ключ и молчащее соединение.
        assert_eq!(Method::Aes128Cfb.key_len(), 16);
        assert_eq!(Method::Aes192Cfb.key_len(), 24);
        assert_eq!(Method::Aes256Cfb.key_len(), 32);
        assert_eq!(Method::Aes128Ctr.key_len(), 16);
        assert_eq!(Method::Aes256Ctr.key_len(), 32);
        assert_eq!(Method::Rc4Md5.key_len(), 16);
    }

    #[test]
    fn iv_length_is_sixteen_for_every_real_cipher() {
        // Единственное исключение — `none`, у которого шифра и IV нет вовсе.
        for method in ALL {
            if method == Method::None {
                assert_eq!(method.iv_len(), 0);
            } else {
                assert_eq!(method.iv_len(), 16, "{}", method.name());
            }
        }
    }

    #[test]
    fn none_does_not_encrypt() {
        assert!(!Method::None.encrypts());
        for method in ALL {
            if method != Method::None {
                assert!(method.encrypts(), "{}", method.name());
            }
        }
    }
}
