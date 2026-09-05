//! Имя надстройки `protocol`: как она пишется в настройках и ссылках `ssr://`.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{ShadowsocksrError, ShadowsocksrResult};

/// Надстройка `protocol` — формат кадра поверх потокового шифра.
///
/// Список короче, чем у эталона: там ещё есть `auth_sha1_v4` и
/// `auth_chain_a`/`auth_chain_b` (свой генератор случайных чисел, привязанный
/// к ключу). Они не реализованы в этой версии крейта — см. документ крейта,
/// раздел «Чего здесь нет».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolMethod {
    /// Без надстройки: то, что дал шифр, то и есть кадр. Как у обычного
    /// Shadowsocks — адрес назначения и данные идут без рамок и без меток.
    Origin,
    /// Кадры с HMAC-MD5, разовый заголовок с меткой времени на соединение.
    AuthAes128Md5,
    /// То же самое, но HMAC-SHA1 — на десять байт длиннее ключ хэша, только
    /// и разницы.
    AuthAes128Sha1,
}

impl Serialize for ProtocolMethod {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self.name())
    }
}

impl<'de> Deserialize<'de> for ProtocolMethod {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let name = String::deserialize(de)?;
        Self::parse(&name).map_err(serde::de::Error::custom)
    }
}

impl Default for ProtocolMethod {
    /// Пусто в ссылках `ssr://` значит именно это — кадрирования нет вовсе.
    fn default() -> Self {
        Self::Origin
    }
}

impl ProtocolMethod {
    /// Разбирает имя так, как его пишут в ссылках `ssr://`.
    pub fn parse(name: &str) -> ShadowsocksrResult<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "" | "origin" => Ok(Self::Origin),
            "auth_aes128_md5" => Ok(Self::AuthAes128Md5),
            "auth_aes128_sha1" => Ok(Self::AuthAes128Sha1),
            other => Err(ShadowsocksrError::UnknownProtocol(other.to_owned())),
        }
    }

    /// Имя в настройках.
    pub fn name(self) -> &'static str {
        match self {
            Self::Origin => "origin",
            Self::AuthAes128Md5 => "auth_aes128_md5",
            Self::AuthAes128Sha1 => "auth_aes128_sha1",
        }
    }

    /// Есть ли у надстройки настоящая проверка подлинности (HMAC), а не
    /// просто передача байт как есть.
    ///
    /// У `origin` отказа по паролю нет вовсе: сервер с другим паролем
    /// расшифрует заголовок в мусор и промолчит. У `auth_*` неверный пароль
    /// даёт настоящий, проверяемый отказ ([`crate::error::ShadowsocksrError::Rejected`]).
    pub fn authenticates(self) -> bool {
        !matches!(self, Self::Origin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_method_round_trips_through_its_name() {
        for method in [
            ProtocolMethod::Origin,
            ProtocolMethod::AuthAes128Md5,
            ProtocolMethod::AuthAes128Sha1,
        ] {
            assert_eq!(
                ProtocolMethod::parse(method.name()).expect("разбирается"),
                method
            );
        }
    }

    #[test]
    fn an_empty_setting_means_origin() {
        assert_eq!(
            ProtocolMethod::parse("").expect("разбирается"),
            ProtocolMethod::Origin
        );
    }

    #[test]
    fn an_unimplemented_protocol_is_reported_not_guessed() {
        // `auth_chain_a` существует у эталона (и самый дорогой в реализации:
        // свой генератор случайных чисел), но не реализован здесь.
        let err = ProtocolMethod::parse("auth_chain_a").expect_err("не реализован");
        assert!(err.to_string().contains("auth_chain_a"), "{err}");
    }

    #[test]
    fn only_auth_methods_authenticate() {
        assert!(!ProtocolMethod::Origin.authenticates());
        assert!(ProtocolMethod::AuthAes128Md5.authenticates());
        assert!(ProtocolMethod::AuthAes128Sha1.authenticates());
    }
}
