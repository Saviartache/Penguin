//! Параметры: адрес сервера, пароль, чем поток переносится до него.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_transport::tls::{ALPN_HTTP11, TlsConfig};
use serde::{Deserialize, Serialize};

use crate::error::{BrookError, BrookResult};

/// Чем поток переносится до сервера.
///
/// У эталона это разные подкоманды (`client`, `wsclient`, `wssclient`) с
/// разными адресами сервера; здесь — одно поле, потому что кадр Brook поверх
/// них один и тот же ([`crate::frame`]). Различается только то, как байты
/// доходят до сервера.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// Голый TCP. Единственный режим, где есть ещё и UDP.
    #[default]
    Direct,
    /// WebSocket без TLS.
    Ws,
    /// WebSocket внутри TLS.
    Wss,
}

impl Transport {
    /// Нужны ли путь запроса и заголовок `Host`.
    pub fn is_ws(self) -> bool {
        matches!(self, Self::Ws | Self::Wss)
    }
}

/// Настройки подключения к серверу Brook.
///
/// `Debug` реализован вручную ниже — производный вывел бы пароль в журнал.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrookConfig {
    /// Адрес сервера: `example.com:9999`.
    pub server: String,

    /// Пароль. По сети он не уходит: ключ каждого направления выводится из
    /// него и своего нонса ([`crate::frame::key`]).
    pub password: String,

    /// Чем поток переносится до сервера.
    #[serde(default)]
    pub transport: Transport,

    /// Путь запроса для `ws` и `wss`. Не задан — `/ws`, как у эталона.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Заголовок `Host` для них же. Не задан — берётся из адреса сервера.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// TLS. Значим только при `transport = "wss"`.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Пускать ли UDP.
    ///
    /// Действует только при `transport = "direct"`: у `ws` и `wss` сервер
    /// эталона датаграммы не принимает вовсе — их место занимает отдельный
    /// режим «UDP поверх TCP», которого этот крейт не реализует (см. документ
    /// крейта). Обещать здесь UDP для `ws`/`wss` значило бы терять запросы DNS
    /// молча.
    #[serde(default = "yes")]
    pub udp: bool,
}

/// Умолчание для [`BrookConfig::udp`].
const fn yes() -> bool {
    true
}

// Написано руками, а не выведено: производный `Default` дал бы `udp: false`,
// то есть настройки, собранные в коде, вели бы себя не так, как ровно те же
// настройки, прочитанные из файла.
impl Default for BrookConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            password: String::new(),
            transport: Transport::default(),
            path: None,
            host: None,
            tls: TlsConfig::default(),
            udp: yes(),
        }
    }
}

impl BrookConfig {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> BrookResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| BrookError::config(format!("адрес сервера `{raw}`: {e}")))?;

        if endpoint.ports.is_hopping() {
            return Err(BrookError::config(
                "Brook не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Путь запроса для `ws` и `wss`.
    pub fn ws_path(&self) -> &str {
        match self.path.as_deref().map(str::trim) {
            Some(path) if !path.is_empty() => path,
            // Умолчание эталона (`wsclient.go`, `wssclient.go`): пустой путь
            // в адресе сервера превращается ровно в это.
            _ => "/ws",
        }
    }

    /// Имя узла в заголовке `Host`.
    pub fn ws_host(&self) -> BrookResult<String> {
        if let Some(host) = self
            .host
            .as_deref()
            .map(str::trim)
            .filter(|host| !host.is_empty())
        {
            return Ok(host.to_owned());
        }
        Ok(match self.endpoint()?.0 {
            Address::Domain(domain) => domain,
            Address::Ip(ip) => ip.to_string(),
        })
    }

    /// Что объявлять в ALPN под `wss`, если человек не задал своё.
    ///
    /// `http/1.1`: рукопожатие WebSocket — это обычный запрос `Upgrade`, и
    /// маскироваться под что-то другое незачем.
    pub fn default_alpn(&self) -> &'static [&'static [u8]] {
        &[ALPN_HTTP11]
    }

    /// Пойдёт ли UDP на самом деле.
    ///
    /// Флаг настроек и то, что умеет режим переноса, — разные вещи: у `ws` и
    /// `wss` датаграмм нет вовсе, и обещать их значило бы терять DNS молча.
    pub fn udp_works(&self) -> bool {
        self.udp && self.transport == Transport::Direct
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> BrookResult<()> {
        self.endpoint()?;

        if self.password.is_empty() {
            return Err(BrookError::config(
                "пароль не задан: из него выводится ключ каждого направления",
            ));
        }
        if self.transport.is_ws() {
            self.tls.validate()?;
            if !self.ws_path().starts_with('/') {
                return Err(BrookError::config("путь обязан начинаться с `/`"));
            }
        } else {
            if self.path.is_some() || self.host.is_some() {
                return Err(BrookError::config(
                    "путь и `Host` заданы у прямого TCP: выберите `ws` или `wss`, \
                     либо уберите поля",
                ));
            }
            if tls_is_set(&self.tls) {
                return Err(BrookError::config(
                    "настройки TLS заданы без `transport = \"wss\"`: либо включите \
                     его, либо уберите настройки",
                ));
            }
        }
        Ok(())
    }
}

/// Настройки TLS кто-то трогал.
fn tls_is_set(tls: &TlsConfig) -> bool {
    tls.sni.is_some()
        || tls.insecure
        || tls.pin_sha256.is_some()
        || tls.pin_chain_sha256.is_some()
        || tls.ca.is_some()
        || !tls.alpn.is_empty()
}

// Пароль не должен попасть в журнал ни целиком, ни частями.
impl std::fmt::Debug for BrookConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrookConfig")
            .field("server", &self.server)
            .field("password", &"<скрыт>")
            .field("transport", &self.transport)
            .field("path", &self.path)
            .field("host", &self.host)
            .field("tls", &self.tls)
            .field("udp", &self.udp)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config() -> BrookConfig {
        BrookConfig {
            server: "example.com:9999".to_owned(),
            password: "secret".to_owned(),
            ..BrookConfig::default()
        }
    }

    #[test]
    fn a_good_config_passes() {
        config().validate().expect("настройки верны");
    }

    #[test]
    fn parses_every_notation_of_the_address() {
        let (host, port) = config().endpoint().expect("разбирается");
        assert_eq!(host.as_domain(), Some("example.com"));
        assert_eq!(port, 9999);

        let config = BrookConfig {
            server: "[2001:db8::1]:9999".to_owned(),
            ..config()
        };
        assert!(config.endpoint().expect("разбирается").0.as_ip().is_some());
    }

    #[test]
    fn a_port_range_is_refused() {
        let config = BrookConfig {
            server: "example.com:20000-30000".to_owned(),
            ..config()
        };
        assert!(config.endpoint().is_err());
    }

    #[test]
    fn a_password_is_required() {
        let config = BrookConfig {
            password: String::new(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn udp_needs_both_the_flag_and_the_direct_transport() {
        // Врать об этом нельзя: `capabilities` с чужим `udp` означает
        // запросы DNS, уходящие туда, где их молча потеряют.
        assert!(config().udp_works());

        let off = BrookConfig {
            udp: false,
            ..config()
        };
        assert!(!off.udp_works());

        let ws = BrookConfig {
            transport: Transport::Ws,
            udp: true,
            ..config()
        };
        assert!(!ws.udp_works(), "у ws датаграмм нет вовсе");
    }

    #[test]
    fn ws_settings_belong_to_ws_transports() {
        let config = BrookConfig {
            path: Some("/tunnel".to_owned()),
            ..config()
        };
        assert!(config.validate().is_err());

        let config = BrookConfig {
            transport: Transport::Ws,
            ..config
        };
        config.validate().expect("под `ws` это законно");
    }

    #[test]
    fn tls_settings_without_wss_are_refused() {
        let mut config = config();
        config.tls.sni = Some("cdn.example.com".to_owned());
        assert!(config.validate().is_err());
    }

    #[test]
    fn the_default_ws_path_matches_the_reference() {
        assert_eq!(config().ws_path(), "/ws");

        let config = BrookConfig {
            path: Some("/tunnel".to_owned()),
            transport: Transport::Ws,
            ..config()
        };
        assert_eq!(config.ws_path(), "/tunnel");
    }

    #[test]
    fn the_ws_host_falls_back_to_the_server_domain() {
        let config = BrookConfig {
            transport: Transport::Ws,
            ..config()
        };
        assert_eq!(config.ws_host().expect("вычисляется"), "example.com");

        let config = BrookConfig {
            host: Some("cdn.example.com".to_owned()),
            ..config
        };
        assert_eq!(config.ws_host().expect("вычисляется"), "cdn.example.com");
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let params = json!({ "server": "a.io:1", "passwort": "y" });
        assert!(serde_json::from_value::<BrookConfig>(params).is_err());
    }

    #[test]
    fn the_defaults_are_the_same_whether_they_come_from_code_or_from_a_file() {
        let params = json!({ "server": "a.io:1", "password": "x" });
        let parsed: BrookConfig = serde_json::from_value(params).expect("разбирается");
        let built = BrookConfig::default();
        assert_eq!(parsed.udp, built.udp);
        assert_eq!(parsed.transport, built.transport);
    }

    #[test]
    fn the_password_never_shows_up_in_the_log() {
        let shown = format!("{:?}", config());
        assert!(!shown.contains("secret"), "{shown}");
    }
}
