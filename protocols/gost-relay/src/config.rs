//! Параметры: адрес сервера, имя и пароль, TLS, перенос.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_transport::tls::{ALPN_HTTP11, TlsConfig};
use serde::{Deserialize, Serialize};

use crate::error::{GostRelayError, GostRelayResult};

/// Сколько байт умещает имя или пароль: длина в запросе — один байт.
const MAX_CREDENTIAL: usize = 0xFF;

/// Чем шифруется соединение до сервера.
///
/// В отличие от VLESS и Trojan, у самого GOST Relay TLS нет: `relay.go` не
/// упоминает его вовсе, протокол рассчитан на любой байтовый поток, а какой
/// перед ним транспорт — решает не он. Поэтому умолчание здесь — «ничего»,
/// а не TLS: включать шифрование, которого нет в протоколе по умолчанию,
/// молча значило бы обещать то, чего сервер может не ждать.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    /// TLS.
    Tls,
    /// Ничего. Обычный случай для этого протокола.
    #[default]
    None,
}

/// Чем поток переносится.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// Голый поток.
    #[default]
    Tcp,
    /// WebSocket: соединение выглядит долгоживущей веб-страницей.
    Ws,
    /// `Upgrade` без кадров: то же рукопожатие, дешевле на каждом куске.
    Httpupgrade,
}

impl Transport {
    /// Нужны ли путь и заголовок `Host`.
    pub fn is_http(self) -> bool {
        matches!(self, Self::Ws | Self::Httpupgrade)
    }

    /// Что объявлять в ALPN, если человек не задал своё.
    ///
    /// Голый TCP у GOST Relay ничего не согласует поверх TLS — ALPN здесь
    /// нечем маскировать, в отличие от VLESS, у которого сам протокол
    /// всегда идёт поверх TLS и HTTP/2 — обычное дело для сайта. Пустой
    /// список означает «не объявлять ALPN вовсе».
    pub fn default_alpn(self) -> &'static [&'static [u8]] {
        match self {
            Self::Tcp => &[],
            Self::Ws | Self::Httpupgrade => &[ALPN_HTTP11],
        }
    }
}

/// Настройки подключения к серверу GOST Relay.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GostRelayConfig {
    /// Адрес сервера: `example.com:8443`.
    pub server: String,

    /// Имя для проверки подлинности.
    ///
    /// Пустая строка — то же самое, что отсутствие своего имени: сервер без
    /// настроенных пользователей опознание не спрашивает вовсе.
    #[serde(default)]
    pub username: String,

    /// Пароль. По сети уходит открытым текстом внутри запроса — если нужно
    /// его прятать, транспорт снизу должен быть TLS. В `Debug` не попадает.
    #[serde(default)]
    pub password: String,

    /// Чем шифруется соединение до сервера.
    #[serde(default)]
    pub security: Security,

    /// TLS. Значим при `security = "tls"`.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Чем переносится поток.
    #[serde(default)]
    pub transport: Transport,

    /// Путь запроса для `ws` и `httpupgrade`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Заголовок `Host` для них же.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// Пускать ли UDP.
    ///
    /// UDP здесь — не настоящий `UDP ASSOCIATE`, а поток на каждого
    /// адресата (`crate::datagram`). Причина в документе крейта.
    #[serde(default = "yes")]
    pub udp: bool,
}

/// Умолчание для [`GostRelayConfig::udp`].
const fn yes() -> bool {
    true
}

// Написано руками, а не выведено: производный `Default` дал бы `udp: false`,
// то есть настройки, собранные в коде, вели бы себя не так, как ровно те же
// настройки, прочитанные из файла.
impl Default for GostRelayConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            username: String::new(),
            password: String::new(),
            security: Security::default(),
            tls: TlsConfig::default(),
            transport: Transport::default(),
            path: None,
            host: None,
            udp: yes(),
        }
    }
}

impl GostRelayConfig {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> GostRelayResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| GostRelayError::config(format!("адрес сервера `{raw}`: {e}")))?;

        if endpoint.ports.is_hopping() {
            return Err(GostRelayError::config(
                "GOST Relay не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Путь запроса для `ws` и `httpupgrade`.
    pub fn path(&self) -> &str {
        match self.path.as_deref().map(str::trim) {
            Some(path) if !path.is_empty() => path,
            _ => "/",
        }
    }

    /// Имя узла в заголовке `Host`.
    pub fn host(&self) -> GostRelayResult<String> {
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
    pub fn validate(&self) -> GostRelayResult<()> {
        self.endpoint()?;

        // Длина в запросе — один байт: то, что в него не влезает, сервер
        // прочитает как обрезанное имя или как начало пароля.
        if self.username.len() > MAX_CREDENTIAL {
            return Err(GostRelayError::config(format!(
                "имя длиной {} байт не помещается в один байт длины",
                self.username.len()
            )));
        }
        if self.password.len() > MAX_CREDENTIAL {
            return Err(GostRelayError::config(format!(
                "пароль длиной {} байт не помещается в один байт длины",
                self.password.len()
            )));
        }

        match self.security {
            Security::Tls => self.tls.validate()?,
            Security::None => {
                if tls_is_set(&self.tls) {
                    return Err(GostRelayError::config(
                        "настройки TLS заданы при `security = \"none\"`: \
                         либо включите TLS, либо уберите их",
                    ));
                }
                tracing::warn!(
                    "GOST Relay без TLS: имя, пароль и адрес назначения уходят \
                     по сети открытым текстом — это законно, только если TLS \
                     снимает кто-то перед сервером"
                );
            }
        }
        if !self.transport.is_http() && (self.path.is_some() || self.host.is_some()) {
            return Err(GostRelayError::config(
                "путь и `Host` заданы у переноса без HTTP: выберите `ws` или `httpupgrade`",
            ));
        }
        if self.transport.is_http() && !self.path().starts_with('/') {
            return Err(GostRelayError::config("путь обязан начинаться с `/`"));
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
impl std::fmt::Debug for GostRelayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GostRelayConfig")
            .field("server", &self.server)
            .field("username", &self.username)
            .field("password", &"<скрыт>")
            .field("security", &self.security)
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

    fn config() -> GostRelayConfig {
        GostRelayConfig {
            server: "example.com:8443".to_owned(),
            username: "bob".to_owned(),
            password: "secret".to_owned(),
            ..GostRelayConfig::default()
        }
    }

    #[test]
    fn a_good_config_passes() {
        config().validate().expect("настройки верны");
    }

    #[test]
    fn empty_username_and_password_are_legal() {
        // Сервер без настроенных пользователей опознание не спрашивает —
        // пустые имя и пароль тогда не ошибка, а обычное дело.
        let config = GostRelayConfig {
            username: String::new(),
            password: String::new(),
            ..config()
        };
        config.validate().expect("законно");
    }

    #[test]
    fn a_username_too_long_is_refused() {
        let config = GostRelayConfig {
            username: "a".repeat(256),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_password_too_long_is_refused() {
        let config = GostRelayConfig {
            password: "a".repeat(256),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_port_range_is_refused() {
        let config = GostRelayConfig {
            server: "example.com:20000-30000".to_owned(),
            ..config()
        };
        assert!(config.endpoint().is_err());
    }

    #[test]
    fn tls_settings_without_tls_are_refused() {
        let mut config = config();
        config.tls.sni = Some("cdn.example.com".to_owned());
        assert!(config.validate().is_err());
    }

    #[test]
    fn security_none_alone_is_the_default_and_is_allowed() {
        let config = config();
        assert_eq!(config.security, Security::None);
        config.validate().expect("это законно");
    }

    #[test]
    fn security_tls_is_validated_through_the_shared_tls_config() {
        let config = GostRelayConfig {
            security: Security::Tls,
            tls: TlsConfig {
                pin_sha256: Some("не отпечаток".to_owned()),
                ..TlsConfig::default()
            },
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn http_settings_belong_to_http_transports() {
        let config = GostRelayConfig {
            path: Some("/relay".to_owned()),
            ..config()
        };
        assert!(config.validate().is_err());

        let config = GostRelayConfig {
            transport: Transport::Ws,
            ..config
        };
        config.validate().expect("под `ws` это законно");
    }

    #[test]
    fn the_defaults_are_the_same_whether_they_come_from_code_or_from_a_file() {
        let params = json!({ "server": "a.io:8443" });
        let parsed: GostRelayConfig = serde_json::from_value(params).expect("разбирается");
        let built = GostRelayConfig::default();
        assert_eq!(parsed.udp, built.udp);
        assert_eq!(parsed.security, built.security);
        assert_eq!(parsed.transport, built.transport);
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let params = json!({ "server": "a.io:8443", "usernaem": "bob" });
        assert!(serde_json::from_value::<GostRelayConfig>(params).is_err());
    }

    #[test]
    fn the_password_never_shows_up_in_the_log() {
        let shown = format!("{:?}", config());
        assert!(!shown.contains("secret"), "{shown}");
    }
}
