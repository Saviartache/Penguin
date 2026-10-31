//! Параметры: адрес сервера, UUID, чем шифруется и чем переносится.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_core::uuid::Uuid;
pub use penguin_transport::carrier::Carrier as Transport;
use penguin_transport::tls::TlsConfig;
use serde::{Deserialize, Serialize};

use crate::error::{VlessError, VlessResult};
use crate::reality::RealityConfig;

/// Чем шифруется соединение до сервера (у самого VLESS шифрования нет).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    /// TLS.
    #[default]
    Tls,
    /// Без TLS: UUID и адрес идут открытым текстом; законно, только если TLS снимает сеть доставки.
    None,
    /// Reality ([`VlessConfig::reality`]). «Канал открылся» не значит «сервер узнал»: формула
    /// сверена лишь между `Xray-core` и `sing-box`, а непризнанный клиент попадает на сайт-прикрытие.
    Reality,
}

/// Настройки подключения к серверу VLESS.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlessConfig {
    /// Адрес сервера: `example.com:443`.
    pub server: String,

    /// UUID пользователя; пароля нет, в журнал не уходит.
    pub uuid: Uuid,

    /// Только [`crate::frame::addons::FLOW_VISION`] и только с Reality и `tcp`
    /// ([`crate::vision`]); остальное — ошибка [`Self::validate`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,

    /// Чем шифруется соединение до сервера.
    #[serde(default)]
    pub security: Security,

    /// TLS. Значим при `security = "tls"`.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Reality. Значимо при `security = "reality"`, и только тогда.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<RealityConfig>,

    /// Чем переносится поток: `tcp`, `grpc` или `xhttp`.
    #[serde(default)]
    pub transport: Transport,

    /// Путь `xhttp` или `serviceName` у `grpc` — как в настройках Xray.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// `:authority` для них же.
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

    /// Путь или `serviceName` как задан; умолчание у каждого переноса своё.
    pub fn path(&self) -> &str {
        self.path.as_deref().map_or("", str::trim)
    }

    /// `flow` без пробелов; пустой — `None` (так пишут в ссылках).
    pub fn flow(&self) -> Option<&str> {
        self.flow
            .as_deref()
            .map(str::trim)
            .filter(|flow| !flow.is_empty())
    }

    /// `:authority` запросов `grpc` и `xhttp`: `host`, имя из TLS или адрес.
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
        if let Some(flow) = self.flow() {
            self.validate_flow(flow)?;
        }
        if self.security != Security::Reality && self.reality.is_some() {
            return Err(VlessError::config(
                "настройки `reality` заданы не при `security = \"reality\"`: \
                 либо включите Reality, либо уберите их",
            ));
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
            Security::Reality => {
                let reality = self.reality.as_ref().ok_or_else(|| {
                    VlessError::config(
                        "`security = \"reality\"` требует блок `reality` с ключом сервера",
                    )
                })?;
                reality.validate()?;
                if tls_is_set(&self.tls) {
                    return Err(VlessError::config(
                        "настройки TLS заданы при `security = \"reality\"`: Reality не \
                         использует обычный TLS вовсе — либо уберите их, либо выберите \
                         `security = \"tls\"`",
                    ));
                }
            }
        }
        if !self.transport.uses_path() && (self.path.is_some() || self.host.is_some()) {
            return Err(VlessError::config(
                "путь и `host` заданы у голого потока: выберите `grpc` или `xhttp`",
            ));
        }
        if self.transport.is_quic() && self.security == Security::None {
            return Err(VlessError::config(
                "`transport = \"xhttp\"` требует `security = \"tls\"` (HTTP/3) \
                 или `security = \"reality\"` (HTTP/2)",
            ));
        }
        Ok(())
    }

    /// Vision: только Reality и `tcp`, иначе нет доступа к записям внешнего TLS.
    fn validate_flow(&self, flow: &str) -> VlessResult<()> {
        if flow != crate::frame::addons::FLOW_VISION {
            return Err(VlessError::config(format!(
                "`flow = {flow}` не поддерживается: понимаем только `{vision}`",
                vision = crate::frame::addons::FLOW_VISION,
            )));
        }
        match self.security {
            Security::None => {
                return Err(VlessError::config(format!(
                    "`flow = {flow}` вместе с `security = \"none\"`: Vision разбирает \
                     записи TLS, а без TLS вообще их не будет — либо включите \
                     `security = \"reality\"`, либо уберите `flow`"
                )));
            }
            Security::Tls => {
                return Err(VlessError::config(format!(
                    "`flow = {flow}` поддержан только при `security = \"reality\"`: \
                     Vision пишет TLS-записи в обход шифрования, а `rustls` \
                     (`security = \"tls\"`) не даёт для этого доступа к своему \
                     состоянию — см. `crate::vision`"
                )));
            }
            Security::Reality => {}
        }
        if self.transport != Transport::Tcp {
            return Err(VlessError::config(format!(
                "`flow = {flow}` поддержан только с `transport = \"tcp\"`: перенос \
                 рвёт прямую границу с внешним TLS, которая нужна для переключения"
            )));
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
        let config = VlessConfig {
            uuid: Uuid::nil(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn an_unknown_flow_is_refused_by_name() {
        let config = VlessConfig {
            security: Security::Reality,
            reality: Some(reality()),
            flow: Some("xtls-rprx-splice".to_owned()),
            ..config()
        };
        let err = config.validate().expect_err("не поддерживается");
        assert!(err.to_string().contains("xtls-rprx-splice"), "{err}");
    }

    #[test]
    fn vision_without_reality_is_refused() {
        let config = VlessConfig {
            flow: Some("xtls-rprx-vision".to_owned()),
            ..config()
        };
        let err = config
            .validate()
            .expect_err("rustls не поддерживает Vision");
        assert!(err.to_string().contains("xtls-rprx-vision"), "{err}");
    }

    #[test]
    fn vision_without_any_tls_at_all_is_refused() {
        let config = VlessConfig {
            security: Security::None,
            flow: Some("xtls-rprx-vision".to_owned()),
            ..config()
        };
        let err = config.validate().expect_err("нет TLS-записей вовсе");
        assert!(err.to_string().contains("none"), "{err}");
    }

    #[test]
    fn vision_over_a_transport_other_than_tcp_is_refused() {
        let config = VlessConfig {
            security: Security::Reality,
            reality: Some(reality()),
            transport: Transport::Grpc,
            path: Some("svc".to_owned()),
            flow: Some("xtls-rprx-vision".to_owned()),
            ..config()
        };
        let err = config
            .validate()
            .expect_err("перенос рвёт границу с внешним TLS");
        assert!(err.to_string().contains("tcp"), "{err}");
    }

    #[test]
    fn vision_over_reality_and_tcp_is_the_one_combination_that_works() {
        let config = VlessConfig {
            security: Security::Reality,
            reality: Some(reality()),
            flow: Some("xtls-rprx-vision".to_owned()),
            ..config()
        };
        config.validate().expect("Vision поддержан ровно здесь");
    }

    #[test]
    fn an_empty_flow_is_the_same_as_none() {
        let config = VlessConfig {
            flow: Some("  ".to_owned()),
            ..config()
        };
        config.validate().expect("пустое значение законно");
    }

    #[test]
    fn tls_settings_without_tls_are_refused() {
        let mut config = VlessConfig {
            security: Security::None,
            ..config()
        };
        config.tls.sni = Some("cdn.example.com".to_owned());
        assert!(config.validate().is_err());
    }

    #[test]
    fn security_none_alone_is_allowed() {
        let config = VlessConfig {
            security: Security::None,
            ..config()
        };
        config.validate().expect("это законно");
    }

    fn reality() -> crate::reality::RealityConfig {
        crate::reality::RealityConfig {
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            short_id: String::new(),
            server_name: "www.example.com".to_owned(),
            fingerprint: penguin_utls::Fingerprint::Chrome,
        }
    }

    #[test]
    fn reality_requires_its_own_settings_block() {
        let config = VlessConfig {
            security: Security::Reality,
            ..config()
        };
        let err = config
            .validate()
            .expect_err("без ключа сервера не поднять Reality");
        assert!(err.to_string().contains("reality"), "{err}");
    }

    #[test]
    fn reality_settings_without_reality_security_are_refused() {
        let config = VlessConfig {
            reality: Some(reality()),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn tls_settings_together_with_reality_are_refused() {
        let mut config = VlessConfig {
            security: Security::Reality,
            reality: Some(reality()),
            ..config()
        };
        config.tls.sni = Some("cdn.example.com".to_owned());
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_good_reality_config_passes() {
        let config = VlessConfig {
            security: Security::Reality,
            reality: Some(reality()),
            ..config()
        };
        config.validate().expect("настройки Reality верны");
    }

    #[test]
    fn http_settings_belong_to_http_transports() {
        let config = VlessConfig {
            path: Some("svc".to_owned()),
            ..config()
        };
        assert!(config.validate().is_err());

        for transport in [Transport::Grpc, Transport::Xhttp] {
            let config = VlessConfig {
                transport,
                ..config.clone()
            };
            config.validate().expect("под `grpc` и `xhttp` это законно");
        }
    }

    #[test]
    fn xhttp_needs_tls_or_reality() {
        let over_reality = VlessConfig {
            security: Security::Reality,
            reality: Some(reality()),
            transport: Transport::Xhttp,
            ..config()
        };
        over_reality
            .validate()
            .expect("XHTTP поверх Reality идёт по HTTP/2");

        let bare = VlessConfig {
            security: Security::None,
            transport: Transport::Xhttp,
            ..config()
        };
        assert!(bare.validate().is_err());
    }

    #[test]
    fn websocket_is_gone() {
        let params = json!({ "server": "a.io:443", "uuid": TEXT, "transport": "ws" });
        assert!(serde_json::from_value::<VlessConfig>(params).is_err());
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
