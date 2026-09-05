//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL;
use crate::config::BrookConfig;
use crate::outbound::BrookOutbound;

/// Фабрика Brook.
#[derive(Debug, Default, Clone, Copy)]
pub struct BrookFactory;

impl BrookFactory {
    /// Создаёт фабрику.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<BrookConfig, ProtocolError> {
        serde_json::from_value(params.clone())
            .map_err(|e| ProtocolError::InvalidConfig(format!("Brook: {e}")))
    }
}

#[async_trait]
impl ProtocolFactory for BrookFactory {
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
        // Соединение здесь не поднимается: у Brook его и не бывает
        // постоянного, каждый поток открывает своё.
        Ok(Arc::new(BrookOutbound::new(ctx.id, config, ctx.dialer)?))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn validates_a_good_config() {
        let params = json!({ "server": "example.com:9999", "password": "secret" });
        BrookFactory::new()
            .validate(&params)
            .expect("настройки верны");

        let params = json!({
            "server": "example.com:443",
            "password": "secret",
            "transport": "wss",
            "path": "/tunnel",
            "udp": false,
            "tls": { "sni": "cdn.example.com" }
        });
        BrookFactory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_password() {
        let params = json!({ "server": "example.com:9999" });
        assert!(BrookFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_address_without_a_port() {
        let params = json!({ "server": "example.com", "password": "x" });
        assert!(BrookFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_ws_fields_without_a_ws_transport() {
        let params = json!({
            "server": "example.com:9999",
            "password": "x",
            "path": "/tunnel"
        });
        assert!(BrookFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let params = json!({ "server": "example.com:9999", "passwort": "x" });
        assert!(BrookFactory::new().validate(&params).is_err());
    }

    #[test]
    fn protocol_name_is_stable() {
        assert_eq!(BrookFactory::new().protocol(), "brook");
    }
}
