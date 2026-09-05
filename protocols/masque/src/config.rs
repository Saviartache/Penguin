//! Параметры: адрес прокси MASQUE, TLS, необязательный заголовок опознания.
//!
//! RFC 9298 не описывает опознание вовсе — прокси может требовать что угодно
//! поверх обычного HTTP. Поле `authorization` — сырое значение заголовка
//! `Authorization`, которое клиент просто прикладывает к каждому запросу
//! `CONNECT`; какая это схема (`Bearer`, `Basic`), решает сервер, а не этот
//! крейт.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_transport::tls::TlsConfig;
use serde::{Deserialize, Serialize};

use crate::error::{MasqueError, MasqueResult};

/// Настройки подключения к прокси MASQUE.
///
/// `Debug` реализован вручную ниже — производный вывел бы заголовок
/// опознания в журнал.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MasqueConfig {
    /// Адрес прокси: `example.com:443`.
    pub server: String,

    /// Значение заголовка `Authorization` для каждого запроса `CONNECT-UDP`.
    ///
    /// В `Debug` не попадает: вывод пишется вручную ниже.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<String>,

    /// TLS до прокси.
    #[serde(default)]
    pub tls: TlsConfig,
}

impl MasqueConfig {
    /// Разбирает адрес прокси.
    pub fn endpoint(&self) -> MasqueResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| MasqueError::config(format!("адрес прокси `{raw}`: {e}")))?;

        // У CONNECT-UDP нет смены порта на ходу — прокси один и слушает один порт.
        if endpoint.ports.is_hopping() {
            return Err(MasqueError::config(
                "masque не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Имя, которое подставляется в TLS.
    ///
    /// Явно заданное `sni` сильнее: прокси за подменённым адресом всё равно
    /// ждёт своё имя, и без этого сертификат не сойдётся.
    pub fn server_name(&self) -> MasqueResult<String> {
        if let Some(sni) = &self.tls.sni
            && !sni.is_empty()
        {
            return Ok(sni.clone());
        }
        Ok(match self.endpoint()?.0 {
            Address::Domain(domain) => domain,
            // Без скобок и для IPv6: rustls ждёт сам адрес.
            Address::Ip(ip) => ip.to_string(),
        })
    }

    /// Проверяет настройки, не устанавливая соединения.
    pub fn validate(&self) -> MasqueResult<()> {
        self.endpoint()?;
        self.server_name()?;
        self.tls.validate()?;
        Ok(())
    }
}

// Заголовок опознания не должен попасть в журнал ни целиком, ни частями.
impl std::fmt::Debug for MasqueConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasqueConfig")
            .field("server", &self.server)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "<скрыт>"),
            )
            .field("tls", &self.tls)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config(server: &str) -> MasqueConfig {
        MasqueConfig {
            server: server.to_owned(),
            ..MasqueConfig::default()
        }
    }

    #[test]
    fn parses_every_notation_of_the_address() {
        let (host, port) = config("example.com:443").endpoint().expect("разбирается");
        assert_eq!(host.as_domain(), Some("example.com"));
        assert_eq!(port, 443);

        let (host, _) = config("[2001:db8::1]:443").endpoint().expect("разбирается");
        assert!(host.as_ip().is_some_and(|ip| ip.is_ipv6()));
    }

    #[test]
    fn refuses_a_port_range() {
        assert!(config("example.com:20000-30000").endpoint().is_err());
    }

    #[test]
    fn refuses_an_address_without_a_port() {
        assert!(config("example.com").endpoint().is_err());
    }

    #[test]
    fn the_tls_name_falls_back_to_the_address() {
        let config = config("example.com:443");
        assert_eq!(config.server_name().expect("имя"), "example.com");

        let mut config = config;
        config.tls.sni = Some("real.example.com".to_owned());
        assert_eq!(config.server_name().expect("имя"), "real.example.com");
    }

    #[test]
    fn an_ip_proxy_needs_no_sni() {
        let config = config("203.0.113.5:443");
        assert_eq!(config.server_name().expect("имя"), "203.0.113.5");
        config.validate().expect("настройки верны");
    }

    #[test]
    fn rejects_an_unknown_field() {
        let raw = json!({ "server": "example.com:443", "passwort": "y" });
        assert!(serde_json::from_value::<MasqueConfig>(raw).is_err());
    }

    #[test]
    fn debug_hides_the_authorization_header() {
        let config = MasqueConfig {
            authorization: Some("Bearer секрет".to_owned()),
            ..config("example.com:443")
        };
        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains("секрет"),
            "заголовок в Debug: {rendered}"
        );
        assert!(rendered.contains("<скрыт>"));
    }
}
