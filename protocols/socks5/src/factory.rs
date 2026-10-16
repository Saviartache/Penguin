//! Регистрация протокола: разбор конфигурации и сборка направления.
//!

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory, parse_params};
use penguin_proto::outbound::Outbound;

use crate::config::Socks5Config;
use crate::outbound::Socks5Outbound;
use crate::{PROTOCOL, PROTOCOL_TLS};

/// Фабрика SOCKS5; две записи в реестре: с TLS и без.
#[derive(Debug, Default, Clone, Copy)]
pub struct Socks5Factory {
    /// Заворачивать ли разговор с прокси в TLS.
    secure: bool,
}

impl Socks5Factory {
    /// Разговор с прокси в открытую.
    pub fn new() -> Self {
        Self { secure: false }
    }

    /// Разговор с прокси внутри TLS.
    pub fn tls() -> Self {
        Self { secure: true }
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<Socks5Config, ProtocolError> {
        parse_params("SOCKS5", params)
    }
}

#[async_trait]
impl ProtocolFactory for Socks5Factory {
    fn protocol(&self) -> &'static str {
        if self.secure { PROTOCOL_TLS } else { PROTOCOL }
    }

    fn validate(&self, params: &serde_json::Value) -> Result<(), ProtocolError> {
        Self::parse(params)?
            .validate(self.secure)
            .map_err(Into::into)
    }

    /// Пробное соединение: иначе «Подключено» горело бы и без прокси, и с неверным паролем.
    async fn build(
        &self,
        ctx: BuildContext,
        params: &serde_json::Value,
    ) -> Result<Arc<dyn Outbound>, ProtocolError> {
        let config = Self::parse(params)?;
        let outbound = Socks5Outbound::new(ctx.id, config, self.secure, ctx.dialer)?;
        outbound.verify().await?;
        Ok(Arc::new(outbound))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn validates_a_good_config() {
        let params = json!({ "server": "127.0.0.1:1080" });
        Socks5Factory::new()
            .validate(&params)
            .expect("настройки верны");

        let params = json!({
            "server": "proxy.example.com:1080",
            "username": "penguin",
            "password": "secret",
            "udp": false
        });
        Socks5Factory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_address() {
        assert!(Socks5Factory::new().validate(&json!({})).is_err());
    }

    #[test]
    fn rejects_an_address_without_a_port() {
        let params = json!({ "server": "127.0.0.1" });
        assert!(Socks5Factory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let params = json!({ "server": "127.0.0.1:1080", "passwort": "y" });
        assert!(Socks5Factory::new().validate(&params).is_err());
    }

    #[test]
    fn protocol_name_is_stable() {
        assert_eq!(Socks5Factory::new().protocol(), "socks5");
        assert_eq!(Socks5Factory::tls().protocol(), "socks5-tls");
    }

    #[test]
    fn tls_settings_belong_to_the_tls_protocol_only() {
        let params = json!({
            "server": "127.0.0.1:1080",
            "tls": { "sni": "proxy.example.com" }
        });
        assert!(Socks5Factory::new().validate(&params).is_err());
        Socks5Factory::tls()
            .validate(&params)
            .expect("под TLS это законно");
    }
}
