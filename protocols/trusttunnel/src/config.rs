//! Параметры: адрес сервера, имя и пароль, TLS.
//!
//! TLS обязателен всегда, а не флагом: у TrustTunnel нет своего рукопожатия
//! вовсе (`PROTOCOL.md`, §1.1) — вся конфиденциальность на TLS, и разговор в
//! открытую был бы не «менее защищённым режимом», а протоколом без единой
//! защиты данных.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use penguin_transport::tls::TlsConfig;
use serde::{Deserialize, Serialize};

use crate::error::{TrustTunnelError, TrustTunnelResult};

/// Настройки подключения к серверу TrustTunnel.
///
/// `Debug` реализован вручную ниже — производный вывел бы пароль в журнал.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustTunnelConfig {
    /// Адрес сервера: `example.com:443`.
    pub server: String,

    /// Имя пользователя.
    pub username: String,

    /// Пароль.
    ///
    /// В `Debug` не попадает: вывод пишется вручную ниже.
    pub password: String,

    /// TLS до сервера.
    #[serde(default)]
    pub tls: TlsConfig,
}

impl TrustTunnelConfig {
    /// Разбирает адрес сервера.
    pub fn endpoint(&self) -> TrustTunnelResult<(Address, u16)> {
        let raw = self.server.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| TrustTunnelError::config(format!("адрес сервера `{raw}`: {e}")))?;

        // Диапазон портов — это смена порта на ходу; у CONNECT поверх HTTP/2
        // её нет вовсе: сервер один и слушает один порт (`PROTOCOL.md`, §4.2).
        if endpoint.ports.is_hopping() {
            return Err(TrustTunnelError::config(
                "trusttunnel не умеет смену порта: укажите один порт",
            ));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Имя и пароль для заголовка `proxy-authorization`.
    pub fn credentials(&self) -> (&str, &str) {
        (&self.username, &self.password)
    }

    /// Имя, которое подставляется в TLS.
    ///
    /// Явно заданное `sni` сильнее: сервер за подменённым адресом всё равно
    /// ждёт своё имя, и без этого сертификат не сойдётся.
    pub fn server_name(&self) -> TrustTunnelResult<String> {
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
    pub fn validate(&self) -> TrustTunnelResult<()> {
        self.endpoint()?;
        self.server_name()?;
        self.tls.validate()?;

        // Опознание — часть протокола (`PROTOCOL.md`, §9.1): заголовок
        // `proxy-authorization` уходит на каждом `CONNECT` без исключений, и
        // сервер, ждущий Basic-опознания, откажет пустому имени точно так же,
        // как неверному паролю, — только позже и по сети.
        if self.username.is_empty() {
            return Err(TrustTunnelError::config(
                "не задано имя пользователя: опознание обязательно на каждом CONNECT",
            ));
        }
        Ok(())
    }
}

// Пароль не должен попасть в журнал ни целиком, ни частями: строка «первые
// четыре символа» — это уже утечка, если паролей у пользователя два-три.
impl std::fmt::Debug for TrustTunnelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustTunnelConfig")
            .field("server", &self.server)
            .field("username", &self.username)
            .field("password", &"<скрыт>")
            .field("tls", &self.tls)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config(server: &str) -> TrustTunnelConfig {
        TrustTunnelConfig {
            server: server.to_owned(),
            username: "penguin".to_owned(),
            password: "secret".to_owned(),
            ..TrustTunnelConfig::default()
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
    fn an_ip_server_needs_no_sni() {
        let config = config("203.0.113.5:443");
        assert_eq!(config.server_name().expect("имя"), "203.0.113.5");
        config.validate().expect("настройки верны");
    }

    #[test]
    fn a_missing_username_is_reported() {
        // Опознание уходит на каждом CONNECT: без имени сервер откажет
        // первому же запросу, и ошибку лучше показать в поле сразу.
        let config = TrustTunnelConfig {
            username: String::new(),
            ..config("example.com:443")
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let raw = json!({
            "server": "example.com:443",
            "username": "penguin",
            "password": "secret",
            "user": "penguin",
        });
        assert!(serde_json::from_value::<TrustTunnelConfig>(raw).is_err());
    }

    #[test]
    fn debug_hides_the_password() {
        let config = config("example.com:443");
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("secret"), "пароль в Debug: {rendered}");
        assert!(rendered.contains("<скрыт>"));
    }
}
