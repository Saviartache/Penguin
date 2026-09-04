//! Параметры: адрес сервера, пароль, TLS и сроки жизни сессий.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_transport::tls::TlsConfig;
use serde::{Deserialize, Serialize};

use crate::error::{AnyTlsError, AnyTlsResult};

/// Как клиент представляется серверу, если в настройках не сказано иначе.
///
/// Поле уходит серверу вместе с настройками сессии и по смыслу — тот же
/// `User-Agent`: сервер собирает по нему статистику совместимости. Эталон
/// просит писать правду, и мы пишем правду. Поле в настройках есть затем,
/// чтобы правду можно было не писать: некоторые продавцы доступа по нему
/// ограничивают, а увидеть его может только сам сервер.
pub const CLIENT_NAME: &str = concat!("penguin/", env!("CARGO_PKG_VERSION"));

/// Наименьший разумный срок для сроков сессий, в секундах.
///
/// Меньше — это не настройка, а способ закрывать сессию раньше, чем по ней
/// успеет пройти запрос. Эталон такие значения молча заменяет на умолчание;
/// молча подменять настройку человека мы не будем — скажем.
pub const MIN_SECS: u64 = 5;

/// Настройки подключения к серверу AnyTLS.
///
/// `Debug` реализован вручную ниже — производный вывел бы пароль в журнал.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnyTlsConfig {
    /// Адрес сервера: `example.com:443`.
    pub server: String,

    /// Пароль. По сети уходит его отпечаток SHA-256, а не он сам.
    pub password: String,

    /// TLS. Обязателен: без него AnyTLS не существует.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Как представляться серверу. Не задано — [`CLIENT_NAME`].
    ///
    /// Пустая строка — законное значение: она означает «не представляться».
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,

    /// Как часто проверять простаивающие сессии, в секундах.
    #[serde(default = "half_a_minute")]
    pub idle_check_secs: u64,

    /// После какого простоя закрывать сессию, в секундах.
    #[serde(default = "half_a_minute")]
    pub idle_timeout_secs: u64,

    /// Сколько простаивающих сессий держать про запас.
    ///
    /// Готовая сессия избавляет следующее соединение от рукопожатия TLS. Ноль
    /// — не держать ни одной: соединения будут дороже, зато к серверу не идёт
    /// поток, по которому нечего возить.
    #[serde(default)]
    pub min_idle_sessions: usize,

    /// Пускать ли UDP.
    #[serde(default = "yes")]
    pub udp: bool,
}

/// Умолчание для сроков.
const fn half_a_minute() -> u64 {
    30
}

/// Умолчание для [`AnyTlsConfig::udp`].
const fn yes() -> bool {
    true
}

impl Default for AnyTlsConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            password: String::new(),
            tls: TlsConfig::default(),
            client: None,
            idle_check_secs: half_a_minute(),
            idle_timeout_secs: half_a_minute(),
            min_idle_sessions: 0,
            udp: yes(),
        }
    }
}

impl AnyTlsConfig {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> AnyTlsResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| AnyTlsError::config(format!("адрес сервера `{raw}`: {e}")))?;

        // Диапазон портов — это смена порта на ходу, и у AnyTLS её нет:
        // сессия живёт в одном соединении TLS.
        if endpoint.ports.is_hopping() {
            return Err(AnyTlsError::config(
                "AnyTLS не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Как представляться серверу.
    pub fn client_name(&self) -> &str {
        self.client.as_deref().unwrap_or(CLIENT_NAME)
    }

    /// Что объявлять в ALPN, если человек не задал своё.
    ///
    /// Ничего. У Trojan ALPN — часть маскировки, потому что тот притворяется
    /// сайтом; сервер AnyTLS ни за кого себя не выдаёт, ALPN не требует, и
    /// объявление, которого он не ждёт, оборвало бы рукопожатие. Эталон
    /// молчит здесь ровно так же.
    pub fn default_alpn(&self) -> &'static [&'static [u8]] {
        &[]
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> AnyTlsResult<()> {
        self.endpoint()?;
        self.tls.validate()?;

        if self.password.is_empty() {
            return Err(AnyTlsError::config(
                "пароль не задан: сервер отличает своих только по нему",
            ));
        }
        for (secs, what) in [
            (self.idle_check_secs, "срок проверки простаивающих сессий"),
            (self.idle_timeout_secs, "срок жизни простаивающей сессии"),
        ] {
            if secs < MIN_SECS {
                return Err(AnyTlsError::config(format!(
                    "{what}: {secs} с — меньше {MIN_SECS} с сессия закроется раньше, \
                     чем по ней пройдёт запрос"
                )));
            }
        }
        Ok(())
    }

    /// Как часто проверять простаивающие сессии.
    pub fn idle_check(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.idle_check_secs)
    }

    /// После какого простоя закрывать сессию.
    pub fn idle_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.idle_timeout_secs)
    }
}

// Пароль не должен попасть в журнал ни целиком, ни частями.
impl std::fmt::Debug for AnyTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsConfig")
            .field("server", &self.server)
            .field("password", &"<скрыт>")
            .field("tls", &self.tls)
            .field("client", &self.client)
            .field("idle_check_secs", &self.idle_check_secs)
            .field("idle_timeout_secs", &self.idle_timeout_secs)
            .field("min_idle_sessions", &self.min_idle_sessions)
            .field("udp", &self.udp)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config() -> AnyTlsConfig {
        AnyTlsConfig {
            server: "example.com:443".to_owned(),
            password: "secret".to_owned(),
            ..AnyTlsConfig::default()
        }
    }

    #[test]
    fn parses_every_notation_of_the_address() {
        let (host, port) = config().endpoint().expect("разбирается");
        assert_eq!(host.as_domain(), Some("example.com"));
        assert_eq!(port, 443);

        let config = AnyTlsConfig {
            server: "[2001:db8::1]:8443".to_owned(),
            ..config()
        };
        assert!(config.endpoint().expect("разбирается").0.as_ip().is_some());
    }

    #[test]
    fn a_password_is_required() {
        let config = AnyTlsConfig {
            password: String::new(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_port_range_is_refused() {
        let config = AnyTlsConfig {
            server: "example.com:20000-30000".to_owned(),
            ..config()
        };
        assert!(config.endpoint().is_err());
    }

    #[test]
    fn a_deadline_too_short_to_be_useful_is_refused() {
        // Эталон такое молча заменяет на умолчание. Молчать нельзя: человек
        // поставил число и вправе знать, что оно не действует.
        let short_timeout = AnyTlsConfig {
            idle_timeout_secs: 1,
            ..config()
        };
        assert!(short_timeout.validate().is_err());

        let short_check = AnyTlsConfig {
            idle_check_secs: 0,
            ..config()
        };
        assert!(short_check.validate().is_err());
    }

    #[test]
    fn the_client_tells_the_truth_unless_told_otherwise() {
        assert_eq!(config().client_name(), CLIENT_NAME);
        assert!(CLIENT_NAME.starts_with("penguin/"));

        // Пустая строка — это «не представляться», а не «взять умолчание».
        let config = AnyTlsConfig {
            client: Some(String::new()),
            ..config()
        };
        assert_eq!(config.client_name(), "");
    }

    #[test]
    fn nothing_is_announced_in_alpn() {
        // Сервер AnyTLS ни за кого себя не выдаёт и ALPN не ждёт: объявление
        // оборвало бы рукопожатие.
        assert!(config().default_alpn().is_empty());
    }

    #[test]
    fn the_defaults_are_the_ones_a_profile_gets_without_asking() {
        let config: AnyTlsConfig =
            serde_json::from_value(json!({ "server": "a.io:443", "password": "x" }))
                .expect("разбирается");
        assert!(config.udp);
        assert_eq!(config.idle_check_secs, 30);
        assert_eq!(config.idle_timeout_secs, 30);
        assert_eq!(config.min_idle_sessions, 0);
        config.validate().expect("годится");
    }

    #[test]
    fn an_unknown_field_is_refused() {
        // Опечатка в имени поля не должна молча превращаться в умолчание.
        let params = json!({ "server": "a.io:443", "password": "x", "passwort": "y" });
        assert!(serde_json::from_value::<AnyTlsConfig>(params).is_err());
    }

    #[test]
    fn the_password_never_shows_up_in_the_log() {
        let shown = format!("{:?}", config());
        assert!(!shown.contains("secret"), "{shown}");
    }
}
