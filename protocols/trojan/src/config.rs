//! Параметры: адрес сервера, пароль, TLS и способ переноса.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
pub use penguin_transport::carrier::Carrier as Transport;
use penguin_transport::tls::TlsConfig;
use serde::{Deserialize, Serialize};

use crate::error::{TrojanError, TrojanResult};

/// Настройки подключения к серверу Trojan.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrojanConfig {
    /// Адрес сервера: `example.com:443`.
    pub server: String,

    /// Пароль. По сети уходит его отпечаток SHA-224, а не он сам.
    ///
    /// В `Debug` не попадает: вывод пишется вручную ниже.
    pub password: String,

    /// TLS. Обязателен: без него Trojan — это пароль открытым текстом.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Чем переносится поток: `tcp`, `grpc` или `xhttp`.
    #[serde(default)]
    pub transport: Transport,

    /// Путь `xhttp` или `serviceName` у `grpc` — как в настройках Xray.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// `:authority` для них же.
    ///
    /// Отдельно от адреса; не задан — имя из TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// Пускать ли UDP.
    #[serde(default = "yes")]
    pub udp: bool,
}

/// Умолчание для [`TrojanConfig::udp`].
const fn yes() -> bool {
    true
}

impl TrojanConfig {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> TrojanResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| TrojanError::config(format!("адрес сервера `{raw}`: {e}")))?;

        if endpoint.ports.is_hopping() {
            return Err(TrojanError::config(
                "Trojan не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Путь или `serviceName` как задан; умолчание у каждого переноса своё.
    pub fn path(&self) -> &str {
        self.path.as_deref().map_or("", str::trim)
    }

    /// `:authority` для `grpc` и `xhttp`: явный `host`, имя из TLS, адрес сервера (как у Xray).
    pub fn host(&self) -> TrojanResult<String> {
        if let Some(host) = self
            .host
            .as_deref()
            .map(str::trim)
            .filter(|host| !host.is_empty())
        {
            return Ok(host.to_owned());
        }
        if let Some(sni) = self
            .tls
            .sni
            .as_deref()
            .map(str::trim)
            .filter(|sni| !sni.is_empty())
        {
            return Ok(sni.to_owned());
        }
        Ok(match self.endpoint()?.0 {
            Address::Domain(domain) => domain,
            Address::Ip(ip) => ip.to_string(),
        })
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> TrojanResult<()> {
        self.endpoint()?;
        self.tls.validate()?;

        if self.password.is_empty() {
            return Err(TrojanError::config(
                "пароль не задан: сервер отличает своих только по нему",
            ));
        }
        if !self.transport.uses_path() && (self.path.is_some() || self.host.is_some()) {
            return Err(TrojanError::config(
                "путь и `host` заданы у голого потока: выберите `grpc` или `xhttp`",
            ));
        }
        Ok(())
    }
}

// Пароль в журнал не попадает ни целиком, ни частями (AGENTS §5.2)
impl std::fmt::Debug for TrojanConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrojanConfig")
            .field("server", &self.server)
            .field("password", &"<скрыт>")
            .field("tls", &self.tls)
            .field("transport", &self.transport)
            .field("path", &self.path)
            .field("host", &self.host)
            .field("udp", &self.udp)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config() -> TrojanConfig {
        TrojanConfig {
            server: "example.com:443".to_owned(),
            password: "secret".to_owned(),
            ..TrojanConfig::default()
        }
    }

    #[test]
    fn parses_every_notation_of_the_address() {
        let (host, port) = config().endpoint().expect("разбирается");
        assert_eq!(host.as_domain(), Some("example.com"));
        assert_eq!(port, 443);

        let config = TrojanConfig {
            server: "[2001:db8::1]:443".to_owned(),
            ..config()
        };
        assert!(config.endpoint().expect("разбирается").0.as_ip().is_some());
    }

    #[test]
    fn a_password_is_required() {
        let config = TrojanConfig {
            password: String::new(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_port_range_is_refused() {
        let config = TrojanConfig {
            server: "example.com:20000-30000".to_owned(),
            ..config()
        };
        assert!(config.endpoint().is_err());
    }

    #[test]
    fn http_settings_belong_to_http_transports() {
        let config = TrojanConfig {
            path: Some("svc".to_owned()),
            ..config()
        };
        assert!(config.validate().is_err());

        for transport in [Transport::Grpc, Transport::Xhttp] {
            let config = TrojanConfig {
                transport,
                ..config.clone()
            };
            config.validate().expect("под `grpc` и `xhttp` это законно");
        }
    }

    #[test]
    fn websocket_is_gone() {
        let params = json!({ "server": "a.io:443", "password": "x", "transport": "ws" });
        assert!(serde_json::from_value::<TrojanConfig>(params).is_err());
    }

    #[test]
    fn the_host_falls_back_the_way_a_browser_would() {
        // Явный `host` сильнее имени из TLS, а оно — сильнее адреса.
        let mut config = TrojanConfig {
            transport: Transport::Grpc,
            ..config()
        };
        assert_eq!(config.host().expect("имя"), "example.com");

        config.tls.sni = Some("cdn.example.com".to_owned());
        assert_eq!(config.host().expect("имя"), "cdn.example.com");

        config.host = Some("real.example.com".to_owned());
        assert_eq!(config.host().expect("имя"), "real.example.com");
    }

    #[test]
    fn the_path_goes_as_written() {
        // Умолчание у каждого переноса своё: `//Tun` у gRPC, `/` у XHTTP.
        let config = TrojanConfig {
            transport: Transport::Grpc,
            path: Some(" svc ".to_owned()),
            ..config()
        };
        assert_eq!(config.path(), "svc");
        assert_eq!(
            TrojanConfig {
                path: None,
                ..config
            }
            .path(),
            ""
        );
    }

    #[test]
    fn udp_is_on_unless_it_is_turned_off() {
        let config: TrojanConfig =
            serde_json::from_value(json!({ "server": "a.io:443", "password": "x" }))
                .expect("разбирается");
        assert!(config.udp);
        assert_eq!(config.transport, Transport::Tcp);
    }

    #[test]
    fn an_unknown_field_is_refused() {
        // Опечатка в имени поля не должна молча превращаться в умолчание.
        let params = json!({ "server": "a.io:443", "password": "x", "passwort": "y" });
        assert!(serde_json::from_value::<TrojanConfig>(params).is_err());
    }

    #[test]
    fn the_password_never_shows_up_in_the_log() {
        let shown = format!("{:?}", config());
        assert!(!shown.contains("secret"), "{shown}");
    }
}
