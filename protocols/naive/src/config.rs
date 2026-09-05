//! Параметры: адрес сервера, имя и пароль, TLS.
//!
//! TLS здесь не флаг, как у `http`/`https` в `http-proxy`, — он обязателен
//! всегда. Смысл протокола в том, что снаружи соединение неотличимо от
//! обычного HTTPS до веб-сервера; разговор в открытую эту маскировку снимает
//! целиком, и включать такой режим незачем.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_transport::tls::TlsConfig;
use serde::{Deserialize, Serialize};

use crate::error::{NaiveError, NaiveResult};

/// Настройки подключения к серверу NaiveProxy.
///
/// `Debug` реализован вручную ниже — производный вывел бы пароль в журнал.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NaiveConfig {
    /// Адрес сервера: `example.com:443`.
    pub server: String,

    /// Имя пользователя. Пусто — сервер без пароля (редкость, но легальна).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Пароль.
    ///
    /// В `Debug` не попадает: вывод пишется вручную ниже.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// TLS до сервера.
    #[serde(default)]
    pub tls: TlsConfig,
}

impl NaiveConfig {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> NaiveResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| NaiveError::config(format!("адрес сервера `{raw}`: {e}")))?;

        // Диапазон портов — это смена порта на ходу, а у CONNECT поверх
        // HTTP/2 и HTTP/3 её нет: сервер здесь один и слушает один порт.
        if endpoint.ports.is_hopping() {
            return Err(NaiveError::config(
                "naive не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Имя и пароль, если они заданы.
    pub fn credentials(&self) -> Option<(&str, &str)> {
        let username = self.username.as_deref().filter(|name| !name.is_empty())?;
        Some((username, self.password.as_deref().unwrap_or_default()))
    }

    /// Имя, которое подставляется в TLS.
    ///
    /// Явно заданное `sni` сильнее: сервер за подменённым адресом всё равно
    /// ждёт своё имя, и без этого сертификат не сойдётся.
    pub fn server_name(&self) -> NaiveResult<String> {
        if let Some(sni) = &self.tls.sni
            && !sni.is_empty()
        {
            return Ok(sni.clone());
        }
        Ok(match self.endpoint()?.0 {
            Address::Domain(domain) => domain,
            // Без скобок и для IPv6: rustls ждёт сам адрес.
            Address::Ip(ip) => ip.to_string(),
        })
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> NaiveResult<()> {
        self.endpoint()?;
        self.server_name()?;
        self.tls.validate()?;

        if self.username.as_deref().is_none_or(str::is_empty)
            && self.password.as_deref().is_some_and(|p| !p.is_empty())
        {
            return Err(NaiveError::config(
                "задан пароль без имени пользователя: в заголовке они идут только парой",
            ));
        }
        Ok(())
    }
}

// Пароль не должен попасть в журнал ни целиком, ни частями: строка «первые
// четыре символа» — это уже утечка, если паролей у пользователя два-три.
impl std::fmt::Debug for NaiveConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NaiveConfig")
            .field("server", &self.server)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<скрыт>"))
            .field("tls", &self.tls)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config(server: &str) -> NaiveConfig {
        NaiveConfig {
            server: server.to_owned(),
            ..NaiveConfig::default()
        }
    }

    #[test]
    fn parses_every_notation_of_the_address() {
        let (host, port) = config("example.com:443").endpoint().expect("разбирается");
        assert_eq!(host.as_domain(), Some("example.com"));
        assert_eq!(port, 443);

        let (host, _) = config("[2001:db8::1]:443").endpoint().expect("разбирается");
        assert!(host.as_ip().is_some_and(|ip| ip.is_ipv6()));
    }

    #[test]
    fn refuses_a_port_range() {
        // У CONNECT поверх HTTP/2 и HTTP/3 нет смены порта — сервер один.
        assert!(config("example.com:20000-30000").endpoint().is_err());
    }

    #[test]
    fn refuses_an_address_without_a_port() {
        assert!(config("example.com").endpoint().is_err());
    }

    #[test]
    fn the_tls_name_falls_back_to_the_address() {
        let config = config("example.com:443");
        assert_eq!(config.server_name().expect("имя"), "example.com");

        let mut config = config;
        config.tls.sni = Some("real.example.com".to_owned());
        assert_eq!(config.server_name().expect("имя"), "real.example.com");
    }

    #[test]
    fn an_ip_server_needs_no_sni() {
        let config = config("203.0.113.5:443");
        assert_eq!(config.server_name().expect("имя"), "203.0.113.5");
        config.validate().expect("настройки верны");
    }

    #[test]
    fn a_password_without_a_name_is_reported() {
        let config = NaiveConfig {
            password: Some("секрет".to_owned()),
            ..config("example.com:443")
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let raw = json!({ "server": "example.com:443", "user": "penguin" });
        assert!(serde_json::from_value::<NaiveConfig>(raw).is_err());
    }

    #[test]
    fn debug_hides_the_password() {
        let config = NaiveConfig {
            username: Some("penguin".to_owned()),
            password: Some("секрет".to_owned()),
            ..config("example.com:443")
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("секрет"), "пароль в Debug: {rendered}");
        assert!(rendered.contains("<скрыт>"));
    }
}
