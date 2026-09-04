//! Параметры: адрес сервера, пароль, TLS и способ переноса.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_transport::tls::{ALPN_H2, ALPN_HTTP11, TlsConfig};
use serde::{Deserialize, Serialize};

use crate::error::{TrojanError, TrojanResult};

/// Чем поток переносится внутри TLS.
///
/// Смысл у всех трёх один: доставить байты. Различаются они тем, на что похожи
/// по дороге, и ценой этого сходства.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// Голый поток внутри TLS. Дешевле всех, и это настоящий Trojan.
    #[default]
    Tcp,
    /// WebSocket: соединение выглядит долгоживущей веб-страницей.
    ///
    /// Нужен там, где перед сервером стоит чужой обратный прокси или сеть
    /// доставки: они разбирают HTTP и голый поток до сервера не доносят.
    Ws,
    /// `Upgrade` без кадров: то же рукопожатие, дешевле на каждом куске.
    ///
    /// Годится, когда путь до сервера свой и разбирать кадры по дороге некому.
    Httpupgrade,
}

impl Transport {
    /// Нужны ли путь и заголовок `Host`.
    pub fn is_http(self) -> bool {
        matches!(self, Self::Ws | Self::Httpupgrade)
    }

    /// Что объявлять в ALPN, если человек не задал своё.
    ///
    /// У голого потока — то же, что у браузера на обычном сайте: сервер Trojan
    /// обязан выглядеть этим сайтом, и любое другое объявление выдало бы его
    /// первым же пакетом рукопожатия. У остальных — только `http/1.1`:
    /// рукопожатие там HTTP/1.1, и обещание HTTP/2 сломает обратный прокси.
    pub fn default_alpn(self) -> &'static [&'static [u8]] {
        match self {
            Self::Tcp => &[ALPN_H2, ALPN_HTTP11],
            Self::Ws | Self::Httpupgrade => &[ALPN_HTTP11],
        }
    }
}

/// Настройки подключения к серверу Trojan.
///
/// `Debug` реализован вручную ниже — производный вывел бы пароль в журнал.
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

    /// Чем переносится поток внутри TLS.
    #[serde(default)]
    pub transport: Transport,

    /// Путь запроса для `ws` и `httpupgrade`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Заголовок `Host` для них же.
    ///
    /// Отдельно от адреса: у сервера за общим входом это имя решает, кому
    /// достанется соединение, и совпадать с адресом оно не обязано. Не задан —
    /// берётся имя из TLS.
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

        // Диапазон портов — это смена порта на ходу, и у Trojan её нет:
        // соединение TLS открывается на каждый поток заново.
        if endpoint.ports.is_hopping() {
            return Err(TrojanError::config(
                "Trojan не умеет смену порта: укажите один порт",
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
    ///
    /// Порядок: явный `host`, потом имя из TLS, потом адрес сервера. Пустым он
    /// не бывает: запрос без `Host` — это 400 у любого обратного прокси.
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
        if !self.transport.is_http() && (self.path.is_some() || self.host.is_some()) {
            return Err(TrojanError::config(
                "путь и `Host` заданы у переноса без HTTP: выберите `ws` или `httpupgrade`",
            ));
        }
        if self.transport.is_http() && !self.path().starts_with('/') {
            return Err(TrojanError::config("путь обязан начинаться с `/`"));
        }
        Ok(())
    }
}

// Пароль не должен попасть в журнал ни целиком, ни частями: строка «первые
// четыре символа» — это уже утечка, если паролей у пользователя два-три.
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
        // Сервер отличает своих только по нему, и профиль без пароля — это
        // профиль, который молча уйдёт на чужой сайт.
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
    fn the_default_alpn_looks_like_a_browser() {
        // Сервер обязан выглядеть тем сайтом, за который себя выдаёт: пустой
        // или свой ALPN выдал бы его первым же пакетом.
        assert_eq!(Transport::Tcp.default_alpn(), &[ALPN_H2, ALPN_HTTP11]);
        // А под WebSocket рукопожатие идёт по HTTP/1.1, и обещание HTTP/2
        // сломает обратный прокси перед сервером.
        assert_eq!(Transport::Ws.default_alpn(), &[ALPN_HTTP11]);
    }

    #[test]
    fn http_settings_belong_to_http_transports() {
        // Путь, который никуда не уйдёт, — это настройка, которая молчит.
        let config = TrojanConfig {
            path: Some("/ws".to_owned()),
            ..config()
        };
        assert!(config.validate().is_err());

        let config = TrojanConfig {
            transport: Transport::Ws,
            ..config
        };
        config.validate().expect("под `ws` это законно");
    }

    #[test]
    fn a_path_without_a_slash_is_refused() {
        let config = TrojanConfig {
            transport: Transport::Ws,
            path: Some("ws".to_owned()),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn the_host_falls_back_the_way_a_browser_would() {
        // Явный `host` сильнее имени из TLS, а оно — сильнее адреса.
        let mut config = TrojanConfig {
            transport: Transport::Ws,
            ..config()
        };
        assert_eq!(config.host().expect("имя"), "example.com");

        config.tls.sni = Some("cdn.example.com".to_owned());
        assert_eq!(config.host().expect("имя"), "cdn.example.com");

        config.host = Some("real.example.com".to_owned());
        assert_eq!(config.host().expect("имя"), "real.example.com");
    }

    #[test]
    fn an_empty_path_becomes_a_slash() {
        let config = TrojanConfig {
            transport: Transport::Ws,
            path: Some("   ".to_owned()),
            ..config()
        };
        assert_eq!(config.path(), "/");
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
