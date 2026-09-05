//! Имя надстройки `obfs`: как она пишется в настройках и ссылках `ssr://`.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{ShadowsocksrError, ShadowsocksrResult};

/// Надстройка `obfs` — что видно снаружи ещё до расшифровки.
///
/// Список короче, чем у эталона: там ещё есть `http_post`, `random_head` и
/// `tls1.2_ticket_auth` (полноценное поддельное рукопожатие TLS с проверкой
/// ответа сервера). Они не реализованы в этой версии крейта — см. документ
/// крейта, раздел «Чего здесь нет».
///
/// `serde` написан вручную поверх [`ObfsMethod::parse`], а не выведен:
/// производный принял бы только одно написание на вариант, а пустая строка
/// в ссылках `ssr://` — это тоже `plain`, и текст ошибки для незнакомого
/// имени должен называть его, а не жаловаться на «неизвестный вариант».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfsMethod {
    /// Без обфускации: то, что дал шифр, то и ушло в сокет.
    Plain,
    /// Первый пакет выглядит запросом `GET`, ответ — веб-страницей.
    HttpSimple,
}

impl Serialize for ObfsMethod {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self.name())
    }
}

impl<'de> Deserialize<'de> for ObfsMethod {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let name = String::deserialize(de)?;
        Self::parse(&name).map_err(serde::de::Error::custom)
    }
}

impl Default for ObfsMethod {
    /// Пусто в ссылках `ssr://` значит именно это — обфускации нет вовсе.
    fn default() -> Self {
        Self::Plain
    }
}

impl ObfsMethod {
    /// Разбирает имя так, как его пишут в ссылках `ssr://`.
    pub fn parse(name: &str) -> ShadowsocksrResult<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "" | "plain" | "origin" => Ok(Self::Plain),
            "http_simple" | "http_simple_compatible" => Ok(Self::HttpSimple),
            other => Err(ShadowsocksrError::UnknownObfs(other.to_owned())),
        }
    }

    /// Имя в настройках.
    pub fn name(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::HttpSimple => "http_simple",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_method_round_trips_through_its_name() {
        for method in [ObfsMethod::Plain, ObfsMethod::HttpSimple] {
            assert_eq!(
                ObfsMethod::parse(method.name()).expect("разбирается"),
                method
            );
        }
    }

    #[test]
    fn an_empty_setting_means_plain() {
        // Так пишут в ссылках `ssr://`, когда обфускации нет вовсе.
        assert_eq!(
            ObfsMethod::parse("").expect("разбирается"),
            ObfsMethod::Plain
        );
    }

    #[test]
    fn an_unimplemented_obfs_is_reported_not_guessed() {
        // `tls1.2_ticket_auth` существует у эталона, но не реализован здесь.
        // Молча подставить `plain` вместо него значит выдать желаемое за
        // действительное перед пользователем, который явно просил другое.
        let err = ObfsMethod::parse("tls1.2_ticket_auth").expect_err("не реализован");
        assert!(err.to_string().contains("tls1.2_ticket_auth"), "{err}");
    }
}
