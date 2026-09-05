//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL;
use crate::config::SnellConfig;
use crate::outbound::SnellOutbound;

/// Фабрика Snell.
#[derive(Debug, Default, Clone, Copy)]
pub struct SnellFactory;

impl SnellFactory {
    /// Создаёт фабрику.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<SnellConfig, ProtocolError> {
        serde_json::from_value(params.clone())
            .map_err(|e| ProtocolError::InvalidConfig(format!("Snell: {e}")))
    }
}

#[async_trait]
impl ProtocolFactory for SnellFactory {
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
        Ok(Arc::new(SnellOutbound::new(ctx.id, config, ctx.dialer)?))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn validates_a_good_config() {
        let params = json!({ "server": "example.com:8443", "psk": "secret", "version": 4 });
        SnellFactory::new()
            .validate(&params)
            .expect("настройки верны");

        let params = json!({
            "server": "example.com:8443",
            "psk": "secret",
            "version": 3,
            "obfs": "http",
            "obfs_host": "bing.com",
            "udp": false
        });
        SnellFactory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_version() {
        let params = json!({ "server": "example.com:8443", "psk": "secret" });
        assert!(SnellFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_a_version_that_does_not_exist() {
        let params = json!({ "server": "example.com:8443", "psk": "x", "version": 9 });
        assert!(SnellFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_a_missing_psk() {
        let params = json!({ "server": "example.com:8443", "version": 4 });
        assert!(SnellFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_address_without_a_port() {
        let params = json!({ "server": "example.com", "psk": "x", "version": 4 });
        assert!(SnellFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_unknown_obfuscation() {
        let params = json!({ "server": "a.io:1", "psk": "x", "version": 4, "obfs": "websocket" });
        assert!(SnellFactory::new().validate(&params).is_err());
    }

    #[test]
    fn protocol_name_is_stable() {
        assert_eq!(SnellFactory::new().protocol(), "snell");
    }
}
