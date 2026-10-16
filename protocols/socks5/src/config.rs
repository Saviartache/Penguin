//! Параметры: адрес прокси, имя, пароль, разрешение на UDP.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_transport::tls::TlsConfig;
use serde::{Deserialize, Serialize};

use crate::error::{Socks5Error, Socks5Result};

/// Настройки подключения к прокси SOCKS5.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Socks5Config {
    /// Адрес прокси: `127.0.0.1:1080`.
    pub server: String,

    /// Имя пользователя. Пусто — прокси без пароля.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Пароль; в `Debug` не попадает.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// TLS до прокси (только `socks5-tls`); защищает лишь управляющее соединение, не датаграммы.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Пускать ли UDP: `UDP ASSOCIATE` умеют не все прокси, маршрутизатор должен знать заранее.
    #[serde(default = "yes")]
    pub udp: bool,
}

/// Умолчание для [`Socks5Config::udp`].
const fn yes() -> bool {
    true
}

impl Socks5Config {
    /// Разбирает адрес прокси.
    pub fn endpoint(&self) -> Socks5Result<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| Socks5Error::config(format!("адрес прокси `{raw}`: {e}")))?;

        if endpoint.ports.is_hopping() {
            return Err(Socks5Error::config(
                "SOCKS5 не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Имя и пароль, если прокси их спрашивает; пароль без имени отвергает [`Self::validate`].
    pub fn credentials(&self) -> Option<(&str, &str)> {
        let username = self.username.as_deref().filter(|name| !name.is_empty())?;
        Some((username, self.password.as_deref().unwrap_or_default()))
    }

    /// Заданы ли настройки TLS: в профиле без TLS это ошибка выбора протокола.
    fn tls_is_set(&self) -> bool {
        let tls = &self.tls;
        tls.sni.is_some()
            || tls.insecure
            || tls.pin_sha256.is_some()
            || tls.ca.is_some()
            || !tls.alpn.is_empty()
    }

    /// Проверяет настройки без сети; `secure` — под TLS ли разговор с прокси.
    pub fn validate(&self, secure: bool) -> Socks5Result<()> {
        self.endpoint()?;

        if !secure && self.tls_is_set() {
            return Err(Socks5Error::config(
                "настройки TLS заданы у протокола без TLS: выберите `socks5-tls`",
            ));
        }
        if secure {
            self.tls.validate()?;
        }

        if self.username.as_deref().is_none_or(str::is_empty)
            && self.password.as_deref().is_some_and(|p| !p.is_empty())
        {
            return Err(Socks5Error::config(
                "задан пароль без имени пользователя: в SOCKS5 они идут только парой",
            ));
        }
        if let Some((username, password)) = self.credentials()
            && (username.len() > 255 || password.len() > 255)
        {
            return Err(Socks5Error::config(
                "имя и пароль SOCKS5 не длиннее 255 байт каждый",
            ));
        }
        Ok(())
    }
}

// Пароль в журнал не попадает ни целиком, ни частями (AGENTS §5.2)
impl std::fmt::Debug for Socks5Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5Config")
            .field("server", &self.server)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<скрыт>"))
            .field("udp", &self.udp)
            .field("tls", &self.tls)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config(server: &str) -> Socks5Config {
        Socks5Config {
            server: server.to_owned(),
            username: None,
            password: None,
            tls: TlsConfig::default(),
            udp: true,
        }
    }

    #[test]
    fn parses_every_notation_of_the_address() {
        let (host, port) = config("127.0.0.1:1080").endpoint().expect("разбирается");
        assert!(host.as_ip().is_some());
        assert_eq!(port, 1080);

        let (host, _) = config("proxy.example.com:1080")
            .endpoint()
            .expect("разбирается");
        assert_eq!(host.as_domain(), Some("proxy.example.com"));

        let (host, port) = config("[2001:db8::1]:1080")
            .endpoint()
            .expect("разбирается");
        assert!(host.as_ip().is_some_and(|ip| ip.is_ipv6()));
        assert_eq!(port, 1080);
    }

    #[test]
    fn refuses_a_port_range() {
        assert!(config("127.0.0.1:1080-1090").endpoint().is_err());
    }

    #[test]
    fn refuses_an_address_without_a_port() {
        assert!(config("127.0.0.1").endpoint().is_err());
        assert!(config("").endpoint().is_err());
    }

    #[test]
    fn a_proxy_without_a_password_needs_no_credentials() {
        assert!(config("127.0.0.1:1080").credentials().is_none());
        config("127.0.0.1:1080")
            .validate(false)
            .expect("настройки верны");
    }

    #[test]
    fn an_empty_password_still_counts_as_credentials() {
        let config = Socks5Config {
            username: Some("penguin".to_owned()),
            ..config("127.0.0.1:1080")
        };
        assert_eq!(config.credentials(), Some(("penguin", "")));
        config.validate(false).expect("настройки верны");
    }

    #[test]
    fn a_password_without_a_name_is_reported() {
        let config = Socks5Config {
            password: Some("секрет".to_owned()),
            ..config("127.0.0.1:1080")
        };
        assert!(config.validate(false).is_err());
    }

    #[test]
    fn tls_settings_in_a_plain_profile_are_refused() {
        let mut config = config("127.0.0.1:1080");
        config.tls.insecure = true;
        assert!(config.validate(false).is_err());
        config.validate(true).expect("под TLS это законно");
    }

    #[test]
    fn udp_is_on_unless_it_is_turned_off() {
        let config: Socks5Config =
            serde_json::from_value(json!({ "server": "127.0.0.1:1080" })).expect("разбирается");
        assert!(config.udp);

        let config: Socks5Config =
            serde_json::from_value(json!({ "server": "127.0.0.1:1080", "udp": false }))
                .expect("разбирается");
        assert!(!config.udp);
    }

    #[test]
    fn rejects_an_unknown_field() {
        let raw = json!({ "server": "127.0.0.1:1080", "user": "penguin" });
        assert!(serde_json::from_value::<Socks5Config>(raw).is_err());
    }

    #[test]
    fn debug_hides_the_password() {
        let config = Socks5Config {
            username: Some("penguin".to_owned()),
            password: Some("секрет".to_owned()),
            ..config("127.0.0.1:1080")
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("секрет"), "пароль в Debug: {rendered}");
        assert!(rendered.contains("<скрыт>"));
    }
}
