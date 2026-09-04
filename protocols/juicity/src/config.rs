//! Параметры: адрес сервера, UUID, пароль, TLS.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_core::uuid::Uuid;
use penguin_transport::tls::{ALPN_H3, TlsConfig};
use serde::{Deserialize, Serialize};

use crate::error::{JuicityError, JuicityResult};

/// Настройки подключения к серверу Juicity.
///
/// Ручек здесь заметно меньше, чем у TUIC, и это не упущение. У эталона в
/// настройках есть выбор управления перегрузкой, но в коде все значения
/// сходятся к BBR: спецификация требует поддерживать его как минимум, и
/// другого никто не включает. Ручка, которая делает нас непохожими на всех
/// остальных клиентов и больше ничего, — это не настройка.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JuicityConfig {
    /// Адрес сервера: `example.com:443`.
    pub server: String,

    /// UUID пользователя.
    pub uuid: Uuid,

    /// Пароль.
    ///
    /// По сети он не уходит: из него и UUID выводится отпечаток, привязанный
    /// к рукопожатию TLS. В `Debug` не попадает — за этим следит вывод ниже.
    pub password: String,

    /// TLS.
    ///
    /// Здесь же живёт `pin_chain_sha256` — способ доверять серверу по
    /// отпечатку всей цепочки, который Juicity и придумал. Это **не** то же,
    /// что `insecure`: сервер по-прежнему обязан предъявить ровно ту цепочку,
    /// что названа в настройках.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Пускать ли UDP.
    #[serde(default = "yes")]
    pub udp: bool,
}

/// Умолчание для [`JuicityConfig::udp`].
const fn yes() -> bool {
    true
}

// Написано руками, а не выведено: производный `Default` дал бы `udp: false`,
// то есть настройки, собранные в коде, вели бы себя не так, как ровно те же
// настройки, прочитанные из файла. Расходиться этим двум нельзя.
impl Default for JuicityConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            uuid: Uuid::default(),
            password: String::new(),
            tls: TlsConfig::default(),
            udp: yes(),
        }
    }
}

impl JuicityConfig {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> JuicityResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| JuicityError::config(format!("адрес сервера `{raw}`: {e}")))?;

        // Диапазон портов — это смена порта на ходу, и у Juicity её нет.
        if endpoint.ports.is_hopping() {
            return Err(JuicityError::config(
                "Juicity не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Что объявлять в ALPN, если человек не задал своё.
    ///
    /// `h3`, и это требование спецификации, а не маскировка: сервер, увидев
    /// другое, закроет рукопожатие.
    pub fn default_alpn(&self) -> &'static [&'static [u8]] {
        &[ALPN_H3]
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> JuicityResult<()> {
        self.endpoint()?;
        self.tls.validate()?;

        if self.uuid.is_nil() {
            return Err(JuicityError::config(
                "UUID из одних нулей: сервер отличает своих по нему и паролю",
            ));
        }
        if self.password.is_empty() {
            return Err(JuicityError::config(
                "пароль не задан: из него выводится отпечаток проверки подлинности",
            ));
        }
        Ok(())
    }
}

// Пароль не должен попасть в журнал ни целиком, ни частями.
impl std::fmt::Debug for JuicityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JuicityConfig")
            .field("server", &self.server)
            .field("uuid", &self.uuid)
            .field("password", &"<скрыт>")
            .field("tls", &self.tls)
            .field("udp", &self.udp)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn config() -> JuicityConfig {
        JuicityConfig {
            server: "example.com:443".to_owned(),
            uuid: TEXT.parse().expect("разбирается"),
            password: "secret".to_owned(),
            ..JuicityConfig::default()
        }
    }

    #[test]
    fn parses_every_notation_of_the_address() {
        let (host, port) = config().endpoint().expect("разбирается");
        assert_eq!(host.as_domain(), Some("example.com"));
        assert_eq!(port, 443);

        let config = JuicityConfig {
            server: "[2001:db8::1]:8443".to_owned(),
            ..config()
        };
        assert!(config.endpoint().expect("разбирается").0.as_ip().is_some());
    }

    #[test]
    fn a_uuid_and_a_password_are_both_required() {
        // Отпечаток выводится из обоих: без любого из них сервер не признает.
        let no_uuid = JuicityConfig {
            uuid: Uuid::default(),
            ..config()
        };
        assert!(no_uuid.validate().is_err());

        let no_password = JuicityConfig {
            password: String::new(),
            ..config()
        };
        assert!(no_password.validate().is_err());
    }

    #[test]
    fn a_port_range_is_refused() {
        let config = JuicityConfig {
            server: "example.com:20000-30000".to_owned(),
            ..config()
        };
        assert!(config.endpoint().is_err());
    }

    #[test]
    fn the_alpn_is_the_one_the_spec_demands() {
        // Не маскировка: сервер, увидев другое, закроет рукопожатие.
        assert_eq!(config().default_alpn(), &[ALPN_H3]);
    }

    #[test]
    fn the_chain_fingerprint_comes_in_under_its_own_name_too() {
        // Так это поле называется в настройках эталона; человек копирует
        // строку оттуда, и переименовывать её ему не с чего.
        let params = json!({
            "server": "a.io:443",
            "uuid": TEXT,
            "password": "x",
            "tls": { "pinned_certchain_sha256": "ab".repeat(32) }
        });
        let config: JuicityConfig = serde_json::from_value(params).expect("разбирается");
        assert!(config.tls.pin_chain_sha256.is_some());
        config.validate().expect("годится");
    }

    #[test]
    fn udp_is_on_unless_it_is_turned_off() {
        let params = json!({ "server": "a.io:443", "uuid": TEXT, "password": "x" });
        let config: JuicityConfig = serde_json::from_value(params).expect("разбирается");
        assert!(config.udp);
    }

    #[test]
    fn the_defaults_are_the_same_whether_they_come_from_code_or_from_a_file() {
        // Производный `Default` дал бы `udp: false`, и настройки, собранные в
        // коде, вели бы себя не так, как ровно те же настройки из файла.
        let params = json!({ "server": "a.io:443", "uuid": TEXT, "password": "x" });
        let parsed: JuicityConfig = serde_json::from_value(params).expect("разбирается");
        let built = JuicityConfig::default();
        assert_eq!(parsed.udp, built.udp);
    }

    #[test]
    fn an_unknown_field_is_refused() {
        // Опечатка в имени поля не должна молча превращаться в умолчание.
        let params = json!({ "server": "a.io:443", "uuid": TEXT, "passwort": "y" });
        assert!(serde_json::from_value::<JuicityConfig>(params).is_err());
    }

    #[test]
    fn the_password_never_shows_up_in_the_log() {
        let shown = format!("{:?}", config());
        assert!(!shown.contains("secret"), "{shown}");
    }
}
