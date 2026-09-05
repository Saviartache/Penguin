//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL;
use crate::config::GostRelayConfig;
use crate::outbound::GostRelayOutbound;

/// Фабрика GOST Relay.
#[derive(Debug, Default, Clone, Copy)]
pub struct GostRelayFactory;

impl GostRelayFactory {
    /// Создаёт фабрику.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<GostRelayConfig, ProtocolError> {
        serde_json::from_value(params.clone())
            .map_err(|e| ProtocolError::InvalidConfig(format!("GOST Relay: {e}")))
    }
}

#[async_trait]
impl ProtocolFactory for GostRelayFactory {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn validate(&self, params: &serde_json::Value) -> Result<(), ProtocolError> {
        Self::parse(params)?.validate().map_err(Into::into)
    }

    async fn build(
        &self,
        ctx: BuildContext,
        params: &serde_json::Value,
    ) -> Result<Arc<dyn Outbound>, ProtocolError> {
        let config = Self::parse(params)?;
        let outbound = GostRelayOutbound::new(ctx.id, config, ctx.dialer)?;

        // Проверка доходит до транспорта (сокет, TLS) и там останавливается:
        // заголовку `CmdConnect` нужен настоящий адрес назначения, которого
        // здесь ещё нет. Без неё «Подключено» загоралось бы и на сервере,
        // которого нет.
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
        let params = json!({ "server": "example.com:8443" });
        GostRelayFactory::new()
            .validate(&params)
            .expect("настройки верны");

        let params = json!({
            "server": "example.com:8443",
            "username": "bob",
            "password": "secret",
            "transport": "ws",
            "path": "/relay",
            "host": "cdn.example.com",
            "udp": false,
            "security": "tls",
            "tls": { "sni": "cdn.example.com" }
        });
        GostRelayFactory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_an_address_without_a_port() {
        let params = json!({ "server": "example.com" });
        assert!(GostRelayFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_a_password_without_matching_tls_settings() {
        let params = json!({
            "server": "example.com:8443",
            "security": "none",
            "tls": { "insecure": true }
        });
        assert!(GostRelayFactory::new().validate(&params).is_err());
    }

    #[test]
    fn protocol_name_is_stable() {
        assert_eq!(GostRelayFactory::new().protocol(), "gost-relay");
    }
}
