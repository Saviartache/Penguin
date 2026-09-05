//! Параметры: адрес сервера, имя, пароль, TLS.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_transport::tls::TlsConfig;
use serde::{Deserialize, Serialize};

use crate::error::{OpenConnectError, OpenConnectResult};

/// Настройки подключения к серверу OpenConnect (`ocserv`).
///
/// `Debug` реализован вручную ниже — производный вывел бы пароль в журнал.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenConnectConfig {
    /// Адрес сервера: `vpn.example.com:443`. Порт по умолчанию — 443, как у
    /// обычного HTTPS: `ocserv` слушает там же, где отдаёт страницу входа.
    pub server: String,

    /// Имя пользователя для формы входа.
    pub username: String,

    /// Пароль. По сети уходит внутри тела XML под TLS, не в поле URL и не в
    /// заголовке — так его не увидит ни один журнал прокси по дороге.
    ///
    /// В `Debug` не попадает: вывод пишется вручную ниже.
    pub password: String,

    /// Группа входа, если сервер предлагает выбор (`<select name="group_list">`
    /// в форме `ocserv`). Не задана — берётся первый вариант из списка,
    /// который прислал сервер.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    /// TLS до сервера. Обязателен: без него имя и пароль уходят открытым
    /// текстом на первом же обмене HTTPS.
    #[serde(default)]
    pub tls: TlsConfig,
}

impl OpenConnectConfig {
    /// Разбирает адрес сервера. Порт по умолчанию — 443.
    pub fn endpoint(&self) -> OpenConnectResult<(Address, u16)> {
        let raw = self.server.trim();
        if raw.is_empty() {
            return Err(OpenConnectError::config("адрес сервера не задан"));
        }

        // Порт по умолчанию — 443, как у обычного HTTPS. Голый IPv6 без
        // скобок (`::1`) тоже содержит `:`, и отличить его от `host:port`
        // может только сам разбор: сначала пробуем как есть, и только если
        // это не вышло — как адрес без порта.
        let endpoint: ServerEndpoint = raw
            .parse()
            .or_else(|_| format!("{raw}:443").parse())
            .map_err(|e| OpenConnectError::config(format!("адрес сервера `{raw}`: {e}")))?;

        if endpoint.ports.is_hopping() {
            return Err(OpenConnectError::config(
                "OpenConnect не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Имя узла для заголовка `Host` и для SNI, если он не задан отдельно.
    pub fn host(&self) -> OpenConnectResult<String> {
        Ok(match self.endpoint()?.0 {
            Address::Domain(domain) => domain,
            Address::Ip(ip) => ip.to_string(),
        })
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> OpenConnectResult<()> {
        self.endpoint()?;
        self.tls
            .validate()
            .map_err(|e| OpenConnectError::config(e.to_string()))?;

        if self.username.trim().is_empty() {
            return Err(OpenConnectError::config(
                "имя пользователя не задано: без него форма входа не заполняется",
            ));
        }
        if self.password.is_empty() {
            return Err(OpenConnectError::config(
                "пароль не задан: без него форма входа не заполняется",
            ));
        }
        if let Some(group) = &self.group
            && group.trim().is_empty()
        {
            return Err(OpenConnectError::config(
                "группа задана пустой строкой: либо имя, либо поля нет вовсе",
            ));
        }
        Ok(())
    }
}

// Пароль не должен попасть в журнал ни целиком, ни частями.
impl std::fmt::Debug for OpenConnectConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenConnectConfig")
            .field("server", &self.server)
            .field("username", &self.username)
            .field("password", &"<скрыт>")
            .field("group", &self.group)
            .field("tls", &self.tls)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config() -> OpenConnectConfig {
        OpenConnectConfig {
            server: "vpn.example.com:443".to_owned(),
            username: "ivan".to_owned(),
            password: "secret".to_owned(),
            ..OpenConnectConfig::default()
        }
    }

    #[test]
    fn parses_an_explicit_port() {
        let (host, port) = config().endpoint().expect("разбирается");
        assert_eq!(host.as_domain(), Some("vpn.example.com"));
        assert_eq!(port, 443);
    }

    #[test]
    fn a_missing_port_defaults_to_https() {
        let config = OpenConnectConfig {
            server: "vpn.example.com".to_owned(),
            ..config()
        };
        let (_, port) = config.endpoint().expect("разбирается");
        assert_eq!(port, 443);
    }

    #[test]
    fn a_bracketed_ipv6_server_without_a_port_still_gets_the_default() {
        // Голый IPv6 без скобок (`2001:db8::1`) неотличим от `host:port` по
        // одному только двоеточию, и «умолчание» там означало бы угадывание.
        // Со скобками отличие однозначно, и умолчание законно.
        let config = OpenConnectConfig {
            server: "[2001:db8::1]".to_owned(),
            ..config()
        };
        let (host, port) = config.endpoint().expect("разбирается");
        assert!(host.as_ip().is_some());
        assert_eq!(port, 443);
    }

    #[test]
    fn a_bracketed_ipv6_with_a_port_is_understood() {
        let config = OpenConnectConfig {
            server: "[2001:db8::1]:8443".to_owned(),
            ..config()
        };
        let (_, port) = config.endpoint().expect("разбирается");
        assert_eq!(port, 8443);
    }

    #[test]
    fn a_port_range_is_refused() {
        let config = OpenConnectConfig {
            server: "vpn.example.com:20000-30000".to_owned(),
            ..config()
        };
        assert!(config.endpoint().is_err());
    }

    #[test]
    fn a_username_is_required() {
        let config = OpenConnectConfig {
            username: String::new(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_password_is_required() {
        let config = OpenConnectConfig {
            password: String::new(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn an_empty_group_is_a_mistake_not_a_default() {
        let config = OpenConnectConfig {
            group: Some("   ".to_owned()),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let params = json!({
            "server": "vpn.example.com:443",
            "username": "ivan",
            "password": "secret",
            "opaque": "x"
        });
        assert!(serde_json::from_value::<OpenConnectConfig>(params).is_err());
    }

    #[test]
    fn the_password_never_shows_up_in_the_log() {
        let shown = format!("{:?}", config());
        assert!(!shown.contains("secret"), "{shown}");
    }
}
