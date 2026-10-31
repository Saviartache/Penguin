//! Параметры: адрес сервера, имя в его сертификате, открытый ключ, пароль, перенос.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_transport::tls::TlsConfig;
use serde::{Deserialize, Serialize};

use crate::error::{PingwinError, PingwinResult};
use crate::wire::keys::PUBLIC_LEN;

/// Настройки подключения к серверу Pingwin.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PingwinConfig {
    /// Адрес сервера: `example.com:443`.
    pub server: String,

    /// Открытый ключ сервера, тридцать два байта в base64.
    pub key: String,

    /// Пароль пользователя.
    pub password: String,

    /// Имя в сертификате сервера. Пусто — хост из адреса.
    pub sni: String,

    /// Свой корневой сертификат, если сертификат сервера выписан не
    /// общедоступным центром.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,

    /// Чем идти до сервера.
    pub transport: Transport,
}

/// Перенос до сервера.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// QUIC с форой, следом TCP; кто первый поднялся, тот и работает.
    #[default]
    Auto,
    /// Только HTTP/3 по UDP.
    Quic,
    /// Только HTTP/2 по TCP: там, где UDP режут.
    Tcp,
}

impl PingwinConfig {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> PingwinResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| PingwinError::config(format!("адрес сервера `{raw}`: {e}")))?;
        if endpoint.ports.is_hopping() {
            return Err(PingwinError::config(
                "pingwin не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Открытый ключ сервера.
    pub fn server_public(&self) -> PingwinResult<[u8; PUBLIC_LEN]> {
        let bytes = penguin_core::base64::decode_exact(self.key.trim(), PUBLIC_LEN, "ключ сервера")
            .map_err(|e| PingwinError::config(format!("ключ сервера: {e}")))?;
        bytes
            .first_chunk()
            .copied()
            .ok_or_else(|| PingwinError::config("ключ сервера не тридцати двух байт"))
    }

    /// Имя, по которому проверяется сертификат: `sni` или домен сервера.
    pub fn server_name(&self) -> PingwinResult<String> {
        let sni = self.sni.trim();
        if !sni.is_empty() {
            return Ok(sni.to_owned());
        }
        match self.endpoint()?.0 {
            Address::Domain(domain) => Ok(domain),
            Address::Ip(ip) => Err(PingwinError::config(format!(
                "сервер задан адресом {ip}: укажите имя из его сертификата"
            ))),
        }
    }

    /// TLS до сервера: обычная проверка сертификата на [`Self::server_name`].
    pub fn tls(&self) -> PingwinResult<TlsConfig> {
        let tls = TlsConfig {
            sni: Some(self.server_name()?),
            ca: self.ca.clone(),
            ..TlsConfig::default()
        };
        tls.validate()?;
        Ok(tls)
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> PingwinResult<()> {
        self.endpoint()?;
        self.server_public()?;
        self.tls()?;
        if self.password.is_empty() {
            return Err(PingwinError::config(
                "не задан пароль: без него сервер не отличит одного пользователя от другого",
            ));
        }
        Ok(())
    }
}

// Пароль скрыт (`AGENTS.md` §5.2).
impl std::fmt::Debug for PingwinConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PingwinConfig")
            .field("server", &self.server)
            .field("key", &self.key)
            .field("password", &"<скрыт>")
            .field("sni", &self.sni)
            .field("ca", &self.ca)
            .field("transport", &self.transport)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config() -> PingwinConfig {
        PingwinConfig {
            server: "example.com:443".to_owned(),
            key: penguin_core::base64::encode(&[7u8; PUBLIC_LEN]),
            password: "secret".to_owned(),
            ..PingwinConfig::default()
        }
    }

    #[test]
    fn a_complete_config_passes() {
        config().validate().expect("настройки верны");
    }

    #[test]
    fn refuses_a_port_range_and_an_address_without_a_port() {
        for server in ["example.com:20000-30000", "example.com"] {
            let config = PingwinConfig {
                server: server.to_owned(),
                ..config()
            };
            assert!(config.endpoint().is_err(), "{server}");
        }
    }

    #[test]
    fn a_key_of_the_wrong_length_is_reported_in_the_field() {
        for key in ["", "не base64", &penguin_core::base64::encode(&[7u8; 31])] {
            let config = PingwinConfig {
                key: key.to_owned(),
                ..config()
            };
            assert!(config.server_public().is_err(), "{key}");
        }
    }

    #[test]
    fn the_certificate_name_is_the_host_unless_told_otherwise() {
        assert_eq!(config().server_name().expect("имя"), "example.com");
        let named = PingwinConfig {
            server: "203.0.113.5:443".to_owned(),
            sni: "vpn.example.com".to_owned(),
            ..config()
        };
        assert_eq!(named.server_name().expect("имя"), "vpn.example.com");
    }

    #[test]
    fn an_address_without_a_name_is_refused() {
        let config = PingwinConfig {
            server: "203.0.113.5:443".to_owned(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_missing_password_is_reported() {
        let config = PingwinConfig {
            password: String::new(),
            ..config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let raw = json!({
            "server": "example.com:443",
            "key": "x",
            "password": "secret",
            "zero_rtt": true,
        });
        assert!(serde_json::from_value::<PingwinConfig>(raw).is_err());
    }

    #[test]
    fn the_transport_is_auto_unless_named() {
        assert_eq!(config().transport, Transport::Auto);
        let raw = json!({ "server": "example.com:443", "transport": "tcp" });
        let parsed: PingwinConfig = serde_json::from_value(raw).expect("разбирается");
        assert_eq!(parsed.transport, Transport::Tcp);
        let raw = json!({ "server": "example.com:443", "transport": "ws" });
        assert!(serde_json::from_value::<PingwinConfig>(raw).is_err());
    }

    #[test]
    fn debug_hides_the_password() {
        let rendered = format!("{:?}", config());
        assert!(!rendered.contains("secret"), "пароль в Debug: {rendered}");
    }
}
