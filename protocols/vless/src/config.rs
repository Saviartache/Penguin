//! Параметры: адрес сервера, UUID, чем шифруется и чем переносится.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_core::uuid::Uuid;
use penguin_transport::tls::{ALPN_H2, ALPN_HTTP11, TlsConfig};
use serde::{Deserialize, Serialize};

use crate::error::{VlessError, VlessResult};

/// Чем шифруется соединение до сервера.
///
/// Своего шифрования у VLESS нет вовсе — в этом его смысл: TLS внутри TLS
/// стоит заметно, и второй раз шифровать то, что уже зашифровано, незачем.
/// Значит, шифрует только это поле.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    /// TLS. Обычный случай.
    #[default]
    Tls,
    /// Ничего.
    ///
    /// Законно ровно в одном случае: когда TLS снимает кто-то другой — сеть
    /// доставки перед сервером или соседний тоннель. Само по себе это значит,
    /// что UUID и адрес назначения идут по сети открытым текстом.
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
    pub fn default_alpn(self) -> &'static [&'static [u8]] {
        match self {
            Self::Tcp => &[ALPN_H2, ALPN_HTTP11],
            Self::Ws | Self::Httpupgrade => &[ALPN_HTTP11],
        }
    }
}

/// Настройки подключения к серверу VLESS.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlessConfig {
    /// Адрес сервера: `example.com:443`.
    pub server: String,

    /// UUID пользователя.
    ///
    /// Единственное, что отличает своего от чужого: пароля рядом нет. В
    /// журнал он не уходит — за этим следит сам тип.
    pub uuid: Uuid,

    /// Дополнение к потоку: `xtls-rprx-vision` и подобное.
    ///
    /// Поддерживается только пустое. Vision неотделим от Reality и требует
    /// разбора записей TLS на лету; принять его молча значит подключиться не
    /// тем способом, о котором договорились с сервером.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,

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
    #[serde(default = "yes")]
    pub udp: bool,
}

/// Умолчание для [`VlessConfig::udp`].
const fn yes() -> bool {
    true
}

impl VlessConfig {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> VlessResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| VlessError::config(format!("адрес сервера `{raw}`: {e}")))?;

        if endpoint.ports.is_hopping() {
            return Err(VlessError::config(
                "VLESS не умеет смену порта: укажите один порт",
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
    pub fn host(&self) -> VlessResult<String> {
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
    pub fn validate(&self) -> VlessResult<()> {
        self.endpoint()?;

        if self.uuid.is_nil() {
            return Err(VlessError::config(
                "UUID из одних нулей: сервер отличает своих только по нему",
            ));
        }
        if let Some(flow) = self.flow.as_deref().map(str::trim)
            && !flow.is_empty()
        {
            return Err(VlessError::config(format!(
                "`flow = {flow}` пока не поддерживается: он неотделим от Reality \
                 и требует разбора записей TLS на лету. Оставьте поле пустым"
            )));
        }
        match self.security {
            Security::Tls => self.tls.validate()?,
            Security::None => {
                if tls_is_set(&self.tls) {
                    return Err(VlessError::config(
                        "настройки TLS заданы при `security = \"none\"`: \
                         либо включите TLS, либо уберите их",
                    ));
                }
                tracing::warn!(
                    "VLESS без TLS: UUID и адрес назначения уходят по сети \
                     открытым текстом — это законно, только если TLS снимает \
                     кто-то перед сервером"
                );
            }
        }
        if !self.transport.is_http() && (self.path.is_some() || self.host.is_some()) {
            return Err(VlessError::config(
                "путь и `Host` заданы у переноса без HTTP: выберите `ws` или `httpupgrade`",
            ));
        }
        if self.transport.is_http() && !self.path().starts_with('/') {
            return Err(VlessError::config("путь обязан начинаться с `/`"));
        }
        Ok(())
    }
}

/// Настройки TLS кто-то трогал.
fn tls_is_set(tls: &TlsConfig) -> bool {
    tls.sni.is_some()
        || tls.insecure
        || tls.pin_sha256.is_some()
        || tls.ca.is_some()
        || !tls.alpn.is_empty()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn config() -> VlessConfig {
        VlessConfig {
            server: "example.com:443".to_owned(),
            uuid: TEXT.parse().expect("разбирается"),
            ..VlessConfig::default()
        }
    }

    #[test]
    fn a_good_config_passes() {
        config().validate().expect("настройки верны");
    }

    #[test]
    fn a_nil_uuid_is_refused() {
        // Сервер отличает своих только по нему; нули означают незаполненное
        // поле, а не «вход без имени».
        let config = VlessConfig {
            uuid: Uuid::nil(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_flow_we_cannot_keep_is_refused_by_name() {
        // Принять его молча значит подключаться не тем способом, о котором
        // договорились с сервером, — и получить молчание вместо ошибки.
        let config = VlessConfig {
            flow: Some("xtls-rprx-vision".to_owned()),
            ..config()
        };
        let err = config.validate().expect_err("не поддерживается");
        assert!(err.to_string().contains("xtls-rprx-vision"), "{err}");
    }

    #[test]
    fn an_empty_flow_is_the_same_as_none() {
        // Так его пишут в ссылках: поле есть, значения нет.
        let config = VlessConfig {
            flow: Some("  ".to_owned()),
            ..config()
        };
        config.validate().expect("пустое значение законно");
    }

    #[test]
    fn tls_settings_without_tls_are_refused() {
        // Иначе человек задаёт SNI, видит сохранённый профиль и уверен, что
        // TLS есть, — а UUID всё это время уходит открытым текстом.
        let mut config = VlessConfig {
            security: Security::None,
            ..config()
        };
        config.tls.sni = Some("cdn.example.com".to_owned());
        assert!(config.validate().is_err());
    }

    #[test]
    fn security_none_alone_is_allowed() {
        // Законно, когда TLS снимает сеть доставки перед сервером.
        let config = VlessConfig {
            security: Security::None,
            ..config()
        };
        config.validate().expect("это законно");
    }

    #[test]
    fn http_settings_belong_to_http_transports() {
        let config = VlessConfig {
            path: Some("/ws".to_owned()),
            ..config()
        };
        assert!(config.validate().is_err());

        let config = VlessConfig {
            transport: Transport::Ws,
            ..config
        };
        config.validate().expect("под `ws` это законно");
    }

    #[test]
    fn the_uuid_is_read_from_the_settings() {
        let params = json!({ "server": "a.io:443", "uuid": TEXT });
        let config: VlessConfig = serde_json::from_value(params).expect("разбирается");
        assert_eq!(config.uuid.to_string(), TEXT);
        assert!(config.udp);
        assert_eq!(config.security, Security::Tls);
    }

    #[test]
    fn something_that_is_not_a_uuid_is_refused() {
        // В поле UUID вставляют пароль — обычная ошибка, и ответ на неё
        // должен быть «это не UUID», а не молчание.
        let params = json!({ "server": "a.io:443", "uuid": "просто-пароль" });
        assert!(serde_json::from_value::<VlessConfig>(params).is_err());
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let params = json!({ "server": "a.io:443", "uuid": TEXT, "uid": TEXT });
        assert!(serde_json::from_value::<VlessConfig>(params).is_err());
    }

    #[test]
    fn the_uuid_never_shows_up_in_the_log() {
        let shown = format!("{:?}", config());
        assert!(!shown.contains("b831"), "{shown}");
    }
}
