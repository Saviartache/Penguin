//! Параметры: адрес сервера, шифр, пароль, надстройки `obfs` и `protocol`.
//!
//! Договориться заранее нужно о большем, чем у Shadowsocks: там два поля
//! (метод, пароль), здесь пять — обе надстройки со своими параметрами
//! добавляют собственные степени свободы, и ни у одной нет умолчания,
//! которое было бы безопасно угадать (см. [`crate`], раздел про `validate`).

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use serde::{Deserialize, Serialize};

use crate::crypto::Method;
use crate::error::{ShadowsocksrError, ShadowsocksrResult};
use crate::obfs::ObfsMethod;
use crate::protocol::ProtocolMethod;

/// Настройки подключения к серверу ShadowsocksR.
///
/// `Debug` реализован вручную ниже — производный вывел бы пароль в журнал.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowsocksrConfig {
    /// Адрес сервера: `example.com:8388`.
    pub server: String,

    /// Метод потокового шифрования. Обязателен: умолчание означало бы
    /// подключение под чужим шифром и молчащее соединение.
    pub method: Method,

    /// Пароль. В `Debug` не попадает: вывод пишется вручную ниже.
    pub password: String,

    /// Надстройка `obfs` — внешний вид пакета. Пусто или `"plain"` — без
    /// обфускации.
    #[serde(default)]
    pub obfs: ObfsMethod,

    /// Параметр `obfs`: список хостов через запятую для `http_simple`
    /// (и, после `#`, свои заголовки вместо набора по умолчанию). У `plain`
    /// не используется.
    #[serde(default)]
    pub obfs_param: Option<String>,

    /// Надстройка `protocol` — формат кадра поверх шифра. Пусто или
    /// `"origin"` — без кадрирования, как у обычного Shadowsocks.
    ///
    /// # Почему не `protocol`
    ///
    /// В самом SSR эта настройка зовётся `protocol`, но в наших настройках
    /// это имя уже занято — им выбирается сам протокол
    /// ([`penguin_config::schema::RawOutbound`] вынимает его до того, как
    /// остальное попадёт сюда). Поле с тем же именем было бы просто
    /// недостижимо: записанное в него читалось бы как имя протокола.
    #[serde(default)]
    pub protocol_method: ProtocolMethod,
}

impl ShadowsocksrConfig {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> ShadowsocksrResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| ShadowsocksrError::config(format!("адрес сервера `{raw}`: {e}")))?;

        // Диапазон портов — это смена порта на ходу, и у ShadowsocksR её нет.
        if endpoint.ports.is_hopping() {
            return Err(ShadowsocksrError::config(
                "ShadowsocksR не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> ShadowsocksrResult<()> {
        self.endpoint()?;

        if self.password.is_empty() {
            return Err(ShadowsocksrError::config(
                "пароль не задан: из него выводится ключ, и пустой означает \
                 ключ, который знают все",
            ));
        }
        Ok(())
    }
}

// Пароль не должен попасть в журнал ни целиком, ни частями (AGENTS.md §5.2).
impl std::fmt::Debug for ShadowsocksrConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowsocksrConfig")
            .field("server", &self.server)
            .field("method", &self.method.name())
            .field("password", &"<скрыт>")
            .field("obfs", &self.obfs.name())
            .field("obfs_param", &self.obfs_param)
            .field("protocol_method", &self.protocol_method.name())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config() -> ShadowsocksrConfig {
        ShadowsocksrConfig {
            server: "example.com:8388".to_owned(),
            method: Method::Aes256Cfb,
            password: "secret".to_owned(),
            obfs: ObfsMethod::Plain,
            obfs_param: None,
            protocol_method: ProtocolMethod::Origin,
        }
    }

    #[test]
    fn parses_every_notation_of_the_address() {
        let (host, port) = config().endpoint().expect("разбирается");
        assert_eq!(host.as_domain(), Some("example.com"));
        assert_eq!(port, 8388);
    }

    #[test]
    fn refuses_an_address_without_a_port() {
        let config = ShadowsocksrConfig {
            server: "example.com".to_owned(),
            ..config()
        };
        assert!(config.endpoint().is_err());
    }

    #[test]
    fn a_password_is_required() {
        let config = ShadowsocksrConfig {
            password: String::new(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn the_method_has_no_default() {
        // Угадать шифр нельзя: подставленный молча даёт соединение, которое
        // сервер не сможет расшифровать.
        let params = json!({ "server": "example.com:8388", "password": "x" });
        assert!(serde_json::from_value::<ShadowsocksrConfig>(params).is_err());
    }

    #[test]
    fn obfs_and_protocol_default_to_the_transparent_variant() {
        // Пусто в ссылках `ssr://` означает именно это — не «сервер настроен
        // как-то иначе», а «надстройки нет вовсе».
        let params = json!({
            "server": "example.com:8388",
            "method": "aes-256-cfb",
            "password": "x"
        });
        let config: ShadowsocksrConfig = serde_json::from_value(params).expect("разбирается");
        assert_eq!(config.obfs, ObfsMethod::Plain);
        assert_eq!(config.protocol_method, ProtocolMethod::Origin);
    }

    #[test]
    fn an_unimplemented_obfs_is_refused_at_parse_time() {
        let params = json!({
            "server": "example.com:8388",
            "method": "aes-256-cfb",
            "password": "x",
            "obfs": "tls1.2_ticket_auth"
        });
        assert!(serde_json::from_value::<ShadowsocksrConfig>(params).is_err());
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let params = json!({
            "server": "example.com:8388",
            "method": "aes-256-cfb",
            "password": "x",
            "passwort": "y"
        });
        assert!(serde_json::from_value::<ShadowsocksrConfig>(params).is_err());
    }

    #[test]
    fn the_password_never_shows_up_in_the_log() {
        let shown = format!("{:?}", config());
        assert!(!shown.contains("secret"), "{shown}");
    }
}
