//! Параметры: адрес сервера, PSK, версия, обфускация.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_transport::obfs::Mode;
use serde::{Deserialize, Serialize};

use crate::error::{SnellError, SnellResult};
use crate::version::Version;

/// Имя узла в обфускации, если его не задали.
///
/// То же, что у эталона. Годится оно тем, что к нему и правда ходят все.
pub const DEFAULT_OBFS_HOST: &str = "bing.com";

/// Настройки подключения к серверу Snell.
///
/// `Debug` реализован вручную ниже — производный вывел бы PSK в журнал.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnellConfig {
    /// Адрес сервера: `example.com:8443`.
    pub server: String,

    /// Общий ключ. По сети он не уходит: из него выводится сеансовый.
    pub psk: String,

    /// Версия протокола.
    ///
    /// Обязательна, и умолчания у неё нет нарочно. Версии несовместимы между
    /// собой, а неверная не даёт отказа: сервер расшифровывает первый кусок
    /// другим шифром, видит мусор и молчит. Подставить сюда единицу значило
    /// бы отправить человека искать неисправность в сети.
    pub version: Version,

    /// Чем прикрыто соединение.
    #[serde(default, with = "obfs_mode")]
    pub obfs: Mode,

    /// Имя узла для обфускации. Не задано — [`DEFAULT_OBFS_HOST`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs_host: Option<String>,

    /// Пускать ли UDP.
    ///
    /// Разрешение, а не обещание: до третьей версии датаграмм у протокола нет
    /// вовсе, и там этот флаг ничего не включит.
    #[serde(default = "yes")]
    pub udp: bool,
}

/// Умолчание для [`SnellConfig::udp`].
const fn yes() -> bool {
    true
}

// Написано руками, а не выведено: производный `Default` дал бы `udp: false`,
// то есть настройки, собранные в коде, вели бы себя не так, как ровно те же
// настройки, прочитанные из файла.
impl Default for SnellConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            psk: String::new(),
            version: Version::V4,
            obfs: Mode::None,
            obfs_host: None,
            udp: yes(),
        }
    }
}

impl SnellConfig {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> SnellResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| SnellError::config(format!("адрес сервера `{raw}`: {e}")))?;

        // Диапазон портов — это смена порта на ходу, и у Snell её нет.
        if endpoint.ports.is_hopping() {
            return Err(SnellError::config(
                "Snell не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Имя узла для обфускации.
    pub fn obfs_host(&self) -> &str {
        match self.obfs_host.as_deref().map(str::trim) {
            Some(host) if !host.is_empty() => host,
            _ => DEFAULT_OBFS_HOST,
        }
    }

    /// Пойдут ли датаграммы на самом деле.
    ///
    /// Флаг настроек и умение версии — разные вещи, и врать об этом нельзя:
    /// `capabilities` с чужим `udp` означает запросы DNS, уходящие в
    /// направление, которое их молча потеряет.
    pub fn udp_works(&self) -> bool {
        self.udp && self.version.udp()
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> SnellResult<()> {
        self.endpoint()?;

        if self.psk.is_empty() {
            return Err(SnellError::config(
                "PSK не задан: из него выводится ключ, и сервер отличает своих только по нему",
            ));
        }
        if self.obfs == Mode::None && self.obfs_host.is_some() {
            return Err(SnellError::config(
                "имя узла задано без обфускации: без неё оно никуда не уйдёт",
            ));
        }
        Ok(())
    }
}

/// Способ обфускации в настройках пишется именем, а не числом.
mod obfs_mode {
    use penguin_transport::obfs::Mode;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Читает имя способа.
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<Mode, D::Error> {
        let name = String::deserialize(input)?;
        Mode::parse(&name).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "обфускация `{name}`: бывает `none`, `http` или `tls`"
            ))
        })
    }

    /// Пишет имя способа.
    pub(super) fn serialize<S: Serializer>(mode: &Mode, out: S) -> Result<S::Ok, S::Error> {
        mode.name().serialize(out)
    }
}

// PSK не должен попасть в журнал ни целиком, ни частями.
impl std::fmt::Debug for SnellConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnellConfig")
            .field("server", &self.server)
            .field("psk", &"<скрыт>")
            .field("version", &self.version)
            .field("obfs", &self.obfs)
            .field("obfs_host", &self.obfs_host)
            .field("udp", &self.udp)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config() -> SnellConfig {
        SnellConfig {
            server: "example.com:8443".to_owned(),
            psk: "secret".to_owned(),
            version: Version::V4,
            ..SnellConfig::default()
        }
    }

    #[test]
    fn parses_every_notation_of_the_address() {
        let (host, port) = config().endpoint().expect("разбирается");
        assert_eq!(host.as_domain(), Some("example.com"));
        assert_eq!(port, 8443);

        let config = SnellConfig {
            server: "[2001:db8::1]:8443".to_owned(),
            ..config()
        };
        assert!(config.endpoint().expect("разбирается").0.as_ip().is_some());
    }

    #[test]
    fn a_psk_is_required() {
        let config = SnellConfig {
            psk: String::new(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn the_version_has_no_default_and_must_be_written_out() {
        // Неверная версия даёт молчание, а не отказ: подставить сюда единицу
        // значило бы отправить человека искать неисправность в сети.
        let without = json!({ "server": "a.io:1", "psk": "x" });
        assert!(serde_json::from_value::<SnellConfig>(without).is_err());

        let with = json!({ "server": "a.io:1", "psk": "x", "version": 3 });
        let config: SnellConfig = serde_json::from_value(with).expect("разбирается");
        assert_eq!(config.version, Version::V3);
    }

    #[test]
    fn udp_needs_both_the_flag_and_a_version_that_can_do_it() {
        // Врать об этом нельзя: `capabilities` с чужим `udp` означает
        // запросы DNS, уходящие туда, где их молча потеряют.
        let old = SnellConfig {
            version: Version::V1,
            udp: true,
            ..config()
        };
        assert!(!old.udp_works());

        let off = SnellConfig {
            udp: false,
            ..config()
        };
        assert!(!off.udp_works());
        assert!(config().udp_works());
    }

    #[test]
    fn the_obfuscation_is_written_by_name() {
        let params = json!({ "server": "a.io:1", "psk": "x", "version": 4, "obfs": "http" });
        let config: SnellConfig = serde_json::from_value(params).expect("разбирается");
        assert_eq!(config.obfs, Mode::Http);
        assert_eq!(config.obfs_host(), DEFAULT_OBFS_HOST);

        let params = json!({ "server": "a.io:1", "psk": "x", "version": 4, "obfs": "htp" });
        assert!(serde_json::from_value::<SnellConfig>(params).is_err());
    }

    #[test]
    fn a_host_without_obfuscation_is_a_setting_that_does_nothing() {
        // Молча принять его значит показать человеку настройку, которой нет.
        let config = SnellConfig {
            obfs_host: Some("bing.com".to_owned()),
            ..config()
        };
        assert!(config.validate().is_err());

        let config = SnellConfig {
            obfs: Mode::Tls,
            ..config
        };
        config.validate().expect("под обфускацией это законно");
    }

    #[test]
    fn a_port_range_is_refused() {
        let config = SnellConfig {
            server: "example.com:20000-30000".to_owned(),
            ..config()
        };
        assert!(config.endpoint().is_err());
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let params = json!({ "server": "a.io:1", "psk": "x", "version": 4, "pks": "y" });
        assert!(serde_json::from_value::<SnellConfig>(params).is_err());
    }

    #[test]
    fn the_psk_never_shows_up_in_the_log() {
        let shown = format!("{:?}", config());
        assert!(!shown.contains("secret"), "{shown}");
    }
}
