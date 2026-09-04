//! Параметры: адрес сервера, UUID, пароль, поведение QUIC.

use std::time::Duration;

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_core::uuid::Uuid;
use penguin_transport::tls::{ALPN_H3, TlsConfig};
use serde::{Deserialize, Serialize};

use crate::error::{TuicError, TuicResult};

/// Чем QUIC управляет перегрузкой.
///
/// В отличие от Hysteria 2, своего управления у TUIC нет: берётся то, что
/// умеет сам QUIC. Разница между вариантами — не «быстрее и медленнее», а
/// разные догадки о том, почему потерялся пакет.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Congestion {
    /// Оценивает полосу и задержку напрямую. Держится лучше остальных там,
    /// где потери не означают перегрузку, — на мобильной сети и на дальних
    /// каналах.
    #[default]
    Bbr,
    /// Умолчание современных систем. Осторожнее BBR к соседям по каналу.
    Cubic,
    /// Самый старый и самый осторожный. Нужен там, где два первых ведут себя
    /// непредсказуемо.
    NewReno,
}

/// Чем едут датаграммы.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UdpMode {
    /// Датаграммами QUIC.
    ///
    /// Быстро и без порядка — то, чем UDP и является. Датаграмма длиннее
    /// путевого MTU при этом режется на части: у QUIC датаграмма не
    /// собирается сама.
    #[default]
    Native,
    /// Односторонними потоками QUIC.
    ///
    /// Медленнее и с гарантией доставки, которой у UDP быть не должно, — зато
    /// проходит там, где датаграммы QUIC режут по дороге.
    Quic,
}

/// Настройки подключения к серверу TUIC.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TuicConfig {
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
    #[serde(default)]
    pub tls: TlsConfig,

    /// Чем QUIC управляет перегрузкой.
    #[serde(default)]
    pub congestion: Congestion,

    /// Чем едут датаграммы.
    #[serde(default)]
    pub udp_mode: UdpMode,

    /// Пускать ли UDP.
    #[serde(default = "yes")]
    pub udp: bool,

    /// Как часто напоминать о себе, в секундах.
    ///
    /// Без этого шлюз с преобразованием адресов забывает отображение через
    /// минуту молчания, и соединение умирает, не сказав ни слова.
    #[serde(default = "default_heartbeat")]
    pub heartbeat_secs: u64,

    /// Сколько соединение живёт без единого пакета, в секундах.
    #[serde(default = "default_idle")]
    pub idle_secs: u64,
}

/// Умолчание для [`TuicConfig::udp`].
const fn yes() -> bool {
    true
}

/// Умолчание для [`TuicConfig::heartbeat_secs`].
const fn default_heartbeat() -> u64 {
    10
}

/// Умолчание для [`TuicConfig::idle_secs`].
const fn default_idle() -> u64 {
    30
}

impl TuicConfig {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> TuicResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| TuicError::config(format!("адрес сервера `{raw}`: {e}")))?;

        // Диапазон портов — это смена порта на ходу, и у TUIC её нет:
        // соединение QUIC одно и живёт на одном адресе.
        if endpoint.ports.is_hopping() {
            return Err(TuicError::config(
                "TUIC не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Как часто напоминать о себе.
    pub fn heartbeat(&self) -> Duration {
        Duration::from_secs(self.heartbeat_secs.max(1))
    }

    /// Сколько соединение живёт без единого пакета.
    pub fn idle(&self) -> Duration {
        Duration::from_secs(self.idle_secs.max(1))
    }

    /// Что объявлять в ALPN, если человек не задал своё.
    ///
    /// `h3`: сервер TUIC обязан выглядеть обычным сервером HTTP/3, и любое
    /// другое значение выдало бы его первым же пакетом рукопожатия.
    pub fn default_alpn(&self) -> &'static [&'static [u8]] {
        &[ALPN_H3]
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> TuicResult<()> {
        self.endpoint()?;
        self.tls.validate()?;

        if self.uuid.is_nil() {
            return Err(TuicError::config(
                "UUID из одних нулей: сервер отличает своих по нему и паролю",
            ));
        }
        if self.password.is_empty() {
            return Err(TuicError::config(
                "пароль не задан: из него выводится отпечаток проверки подлинности",
            ));
        }
        // Напоминание реже, чем соединение живёт без пакетов, — это
        // соединение, которое умирает ровно между двумя напоминаниями.
        if self.heartbeat() >= self.idle() {
            return Err(TuicError::config(format!(
                "напоминание раз в {} с при жизни без пакетов {} с: \
                 соединение умрёт между двумя напоминаниями",
                self.heartbeat_secs, self.idle_secs
            )));
        }
        Ok(())
    }
}

// Пароль не должен попасть в журнал ни целиком, ни частями.
impl std::fmt::Debug for TuicConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuicConfig")
            .field("server", &self.server)
            .field("uuid", &self.uuid)
            .field("password", &"<скрыт>")
            .field("tls", &self.tls)
            .field("congestion", &self.congestion)
            .field("udp_mode", &self.udp_mode)
            .field("udp", &self.udp)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn config() -> TuicConfig {
        TuicConfig {
            server: "example.com:443".to_owned(),
            uuid: TEXT.parse().expect("разбирается"),
            password: "secret".to_owned(),
            heartbeat_secs: default_heartbeat(),
            idle_secs: default_idle(),
            ..TuicConfig::default()
        }
    }

    #[test]
    fn a_good_config_passes() {
        config().validate().expect("настройки верны");
    }

    #[test]
    fn a_nil_uuid_is_refused() {
        let config = TuicConfig {
            uuid: Uuid::nil(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_password_is_required() {
        // Из него выводится отпечаток; пустой означает отпечаток, который
        // знают все.
        let config = TuicConfig {
            password: String::new(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_heartbeat_slower_than_the_idle_timeout_is_refused() {
        // Иначе соединение умирает ровно между двумя напоминаниями, и
        // выглядит это как «рвётся раз в полминуты без причины».
        let config = TuicConfig {
            heartbeat_secs: 30,
            idle_secs: 30,
            ..config()
        };
        let err = config.validate().expect_err("не сходится");
        assert!(err.to_string().contains("между двумя"), "{err}");
    }

    #[test]
    fn a_port_range_is_refused() {
        let config = TuicConfig {
            server: "example.com:20000-30000".to_owned(),
            ..config()
        };
        assert!(config.endpoint().is_err());
    }

    #[test]
    fn the_defaults_are_the_ones_the_protocol_expects() {
        let params = json!({ "server": "a.io:443", "uuid": TEXT, "password": "x" });
        let config: TuicConfig = serde_json::from_value(params).expect("разбирается");

        assert_eq!(config.congestion, Congestion::Bbr);
        assert_eq!(config.udp_mode, UdpMode::Native);
        assert!(config.udp);
        assert_eq!(config.default_alpn(), &[ALPN_H3]);
        config.validate().expect("настройки верны");
    }

    #[test]
    fn the_congestion_names_are_the_ones_people_write() {
        for (name, expected) in [
            ("bbr", Congestion::Bbr),
            ("cubic", Congestion::Cubic),
            ("new_reno", Congestion::NewReno),
        ] {
            let params = json!({
                "server": "a.io:443", "uuid": TEXT, "password": "x",
                "congestion": name
            });
            let config: TuicConfig = serde_json::from_value(params).expect("разбирается");
            assert_eq!(config.congestion, expected, "{name}");
        }
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let params = json!({
            "server": "a.io:443", "uuid": TEXT, "password": "x", "passwort": "y"
        });
        assert!(serde_json::from_value::<TuicConfig>(params).is_err());
    }

    #[test]
    fn neither_the_password_nor_the_uuid_shows_up_in_the_log() {
        let shown = format!("{:?}", config());
        assert!(!shown.contains("secret"), "{shown}");
        assert!(!shown.contains("b831"), "{shown}");
    }
}
