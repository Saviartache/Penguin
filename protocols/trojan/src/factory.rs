//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory, parse_params};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL;
use crate::config::TrojanConfig;
use crate::outbound::TrojanOutbound;

/// Фабрика Trojan.
#[derive(Debug, Default, Clone, Copy)]
pub struct TrojanFactory;

impl TrojanFactory {
    /// Создаёт фабрику.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<TrojanConfig, ProtocolError> {
        parse_params("Trojan", params)
    }
}

#[async_trait]
impl ProtocolFactory for TrojanFactory {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn validate(&self, params: &serde_json::Value) -> Result<(), ProtocolError> {
        Self::parse(params)?.validate().map_err(Into::into)
    }

    /// Пробное подключение доходит до сертификата: иначе «Подключено» горело бы и без сервера.
    async fn build(
        &self,
        ctx: BuildContext,
        params: &serde_json::Value,
    ) -> Result<Arc<dyn Outbound>, ProtocolError> {
        let config = Self::parse(params)?;
        let outbound = TrojanOutbound::new(ctx.id, config, ctx.dialer)?;
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
        let params = json!({ "server": "example.com:443", "password": "secret" });
        TrojanFactory::new()
            .validate(&params)
            .expect("настройки верны");

        let params = json!({
            "server": "example.com:443",
            "password": "secret",
            "transport": "grpc",
            "path": "svc",
            "host": "cdn.example.com",
            "udp": false,
            "tls": { "sni": "cdn.example.com" }
        });
        TrojanFactory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_password() {
        let params = json!({ "server": "example.com:443" });
        assert!(TrojanFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_address_without_a_port() {
        let params = json!({ "server": "example.com", "password": "secret" });
        assert!(TrojanFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_unknown_transport() {
        // Опечатка в имени переноса не должна молча превращаться в `tcp`.
        let params = json!({
            "server": "example.com:443",
            "password": "secret",
            "transport": "kcp"
        });
        assert!(TrojanFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let params = json!({
            "server": "example.com:443",
            "password": "secret",
            "passwort": "y"
        });
        assert!(TrojanFactory::new().validate(&params).is_err());
    }

    #[test]
    fn protocol_name_is_stable() {
        // Имя стоит в конфигурациях пользователей — менять его нельзя.
        assert_eq!(TrojanFactory::new().protocol(), "trojan");
    }
}
