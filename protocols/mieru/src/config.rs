//! Параметры: адрес сервера, имя пользователя, пароль, политика соединений.
//!
//! У Mieru нет TLS и нет сертификата — весь протокол это своё шифрование
//! поверх голого TCP (см. документ крейта). Поэтому здесь нет поля `tls`,
//! в отличие от AnyTLS и большинства остальных протоколов этого проекта.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use serde::{Deserialize, Serialize};

use crate::error::{MieruError, MieruResult};

/// Наибольшая длина имени пользователя, какую разумно принять в поле формы.
///
/// Протокол не ограничивает её сам — ограничение только наше, чтобы опечатка
/// в тысячу символов не ушла в PBKDF2 незамеченной.
pub const MAX_USERNAME_LEN: usize = 255;

/// Наименьший разумный срок для сроков простаивающих соединений, в секундах.
pub const MIN_SECS: u64 = 5;

/// Настройки подключения к серверу Mieru.
///
/// `Debug` реализован вручную ниже — производный вывел бы пароль в журнал.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MieruConfig {
    /// Адрес сервера: `example.com:2999`.
    pub server: String,

    /// Имя пользователя. Участвует в выводе ключа — см. `keying`.
    pub username: String,

    /// Пароль. Участвует в выводе ключа вместе с именем пользователя.
    pub password: String,

    /// Сколько сессий-потоков делить на одно TCP-соединение до сервера.
    ///
    /// Это наша собственная политика клиента, а не то, что видно на
    /// проводе: сервер принимает любое число сессий на одном соединении.
    /// Единица отключает переиспользование совсем.
    #[serde(default = "default_sessions_per_connection")]
    pub sessions_per_connection: usize,

    /// Как часто проверять простаивающие соединения, в секундах.
    #[serde(default = "half_a_minute")]
    pub idle_check_secs: u64,

    /// После какого простоя закрывать соединение, в секундах.
    #[serde(default = "half_a_minute")]
    pub idle_timeout_secs: u64,
}

const fn half_a_minute() -> u64 {
    30
}

const fn default_sessions_per_connection() -> usize {
    8
}

impl Default for MieruConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            username: String::new(),
            password: String::new(),
            sessions_per_connection: default_sessions_per_connection(),
            idle_check_secs: half_a_minute(),
            idle_timeout_secs: half_a_minute(),
        }
    }
}

impl MieruConfig {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> MieruResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| MieruError::config(format!("адрес сервера `{raw}`: {e}")))?;

        // Смены порта на ходу у Mieru нет: соединение живёт по одному адресу.
        if endpoint.ports.is_hopping() {
            return Err(MieruError::config(
                "Mieru не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> MieruResult<()> {
        self.endpoint()?;

        if self.username.is_empty() {
            return Err(MieruError::config(
                "имя пользователя не задано: сервер выводит ключ из него и пароля",
            ));
        }
        if self.username.len() > MAX_USERNAME_LEN {
            return Err(MieruError::config(format!(
                "имя пользователя длиной {} символов — больше {MAX_USERNAME_LEN}",
                self.username.len()
            )));
        }
        if self.password.is_empty() {
            return Err(MieruError::config("пароль не задан"));
        }
        if self.sessions_per_connection == 0 {
            return Err(MieruError::config(
                "sessions_per_connection: ноль сессий на соединение — соединением нельзя воспользоваться",
            ));
        }
        for (secs, what) in [
            (
                self.idle_check_secs,
                "срок проверки простаивающих соединений",
            ),
            (
                self.idle_timeout_secs,
                "срок жизни простаивающего соединения",
            ),
        ] {
            if secs < MIN_SECS {
                return Err(MieruError::config(format!(
                    "{what}: {secs} с — меньше {MIN_SECS} с соединение закроется раньше, \
                     чем по нему пройдёт запрос"
                )));
            }
        }
        Ok(())
    }

    /// Как часто проверять простаивающие соединения.
    pub fn idle_check(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.idle_check_secs)
    }

    /// После какого простоя закрывать соединение.
    pub fn idle_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.idle_timeout_secs)
    }
}

// Пароль не должен попасть в журнал ни целиком, ни частями. Имя пользователя
// печатаем как есть: в отличие от пароля, оно не секрет, а его расхождение с
// ожидаемым — частая причина «сервер не отвечает» на этапе разбора.
impl std::fmt::Debug for MieruConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MieruConfig")
            .field("server", &self.server)
            .field("username", &self.username)
            .field("password", &"<скрыт>")
            .field("sessions_per_connection", &self.sessions_per_connection)
            .field("idle_check_secs", &self.idle_check_secs)
            .field("idle_timeout_secs", &self.idle_timeout_secs)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config() -> MieruConfig {
        MieruConfig {
            server: "example.com:2999".to_owned(),
            username: "alice".to_owned(),
            password: "secret".to_owned(),
            ..MieruConfig::default()
        }
    }

    #[test]
    fn parses_every_notation_of_the_address() {
        let (host, port) = config().endpoint().expect("разбирается");
        assert_eq!(host.as_domain(), Some("example.com"));
        assert_eq!(port, 2999);

        let config = MieruConfig {
            server: "[2001:db8::1]:2999".to_owned(),
            ..config()
        };
        assert!(config.endpoint().expect("разбирается").0.as_ip().is_some());
    }

    #[test]
    fn a_username_is_required() {
        let config = MieruConfig {
            username: String::new(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_password_is_required() {
        let config = MieruConfig {
            password: String::new(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn an_absurdly_long_username_is_refused() {
        let config = MieruConfig {
            username: "a".repeat(MAX_USERNAME_LEN + 1),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_port_range_is_refused() {
        let config = MieruConfig {
            server: "example.com:20000-30000".to_owned(),
            ..config()
        };
        assert!(config.endpoint().is_err());
    }

    #[test]
    fn zero_sessions_per_connection_is_refused() {
        let config = MieruConfig {
            sessions_per_connection: 0,
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_deadline_too_short_to_be_useful_is_refused() {
        let short_timeout = MieruConfig {
            idle_timeout_secs: 1,
            ..config()
        };
        assert!(short_timeout.validate().is_err());
    }

    #[test]
    fn the_defaults_are_the_ones_a_profile_gets_without_asking() {
        let config: MieruConfig = serde_json::from_value(json!({
            "server": "a.io:2999",
            "username": "alice",
            "password": "x"
        }))
        .expect("разбирается");
        assert_eq!(config.sessions_per_connection, 8);
        assert_eq!(config.idle_check_secs, 30);
        assert_eq!(config.idle_timeout_secs, 30);
        config.validate().expect("годится");
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let params = json!({
            "server": "a.io:2999",
            "username": "alice",
            "password": "x",
            "passwort": "y"
        });
        assert!(serde_json::from_value::<MieruConfig>(params).is_err());
    }

    #[test]
    fn the_password_never_shows_up_in_the_log() {
        let shown = format!("{:?}", config());
        assert!(!shown.contains("secret"), "{shown}");
        // А вот имя пользователя — не секрет, его видно.
        assert!(shown.contains("alice"), "{shown}");
    }
}
