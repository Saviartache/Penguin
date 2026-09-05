//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL;
use crate::config::MieruConfig;
use crate::outbound::MieruOutbound;

/// Фабрика Mieru.
#[derive(Debug, Default, Clone, Copy)]
pub struct MieruFactory;

impl MieruFactory {
    /// Создаёт фабрику.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<MieruConfig, ProtocolError> {
        serde_json::from_value(params.clone())
            .map_err(|e| ProtocolError::InvalidConfig(format!("Mieru: {e}")))
    }
}

#[async_trait]
impl ProtocolFactory for MieruFactory {
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
        // Соединение здесь не поднимается: первое неявное соединение
        // заводится первой сессией.
        Ok(Arc::new(MieruOutbound::new(ctx.id, config, ctx.dialer)?))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn validates_a_good_config() {
        let params = json!({
            "server": "example.com:2999",
            "username": "alice",
            "password": "secret"
        });
        MieruFactory::new()
            .validate(&params)
            .expect("настройки верны");

        let params = json!({
            "server": "example.com:2999",
            "username": "alice",
            "password": "secret",
            "sessions_per_connection": 1,
            "idle_check_secs": 60,
            "idle_timeout_secs": 120
        });
        MieruFactory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_username() {
        let params = json!({ "server": "example.com:2999", "password": "secret" });
        assert!(MieruFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_a_missing_password() {
        let params = json!({ "server": "example.com:2999", "username": "alice" });
        assert!(MieruFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_address_without_a_port() {
        let params = json!({ "server": "example.com", "username": "alice", "password": "x" });
        assert!(MieruFactory::new().validate(&params).is_err());
    }

    #[test]
    fn protocol_name_is_stable() {
        assert_eq!(MieruFactory::new().protocol(), "mieru");
    }
}
