//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL;
use crate::config::JuicityConfig;
use crate::outbound::JuicityOutbound;

/// Фабрика Juicity.
#[derive(Debug, Default, Clone, Copy)]
pub struct JuicityFactory;

impl JuicityFactory {
    /// Создаёт фабрику.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<JuicityConfig, ProtocolError> {
        serde_json::from_value(params.clone())
            .map_err(|e| ProtocolError::InvalidConfig(format!("Juicity: {e}")))
    }
}

#[async_trait]
impl ProtocolFactory for JuicityFactory {
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
        // Соединение здесь не поднимается: первое заводит первый поток.
        // Включённый профиль не обязан держать соединение QUIC.
        Ok(Arc::new(JuicityOutbound::new(ctx.id, config, ctx.dialer)?))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn validates_a_good_config() {
        let params = json!({ "server": "example.com:443", "uuid": TEXT, "password": "secret" });
        JuicityFactory::new()
            .validate(&params)
            .expect("настройки верны");

        let params = json!({
            "server": "example.com:8443",
            "uuid": TEXT,
            "password": "secret",
            "udp": false,
            "tls": { "sni": "cdn.example.com", "pinned_certchain_sha256": "ab".repeat(32) }
        });
        JuicityFactory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_password() {
        let params = json!({ "server": "example.com:443", "uuid": TEXT });
        assert!(JuicityFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_something_that_is_not_a_uuid() {
        let params = json!({ "server": "example.com:443", "uuid": "пароль", "password": "x" });
        assert!(JuicityFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_address_without_a_port() {
        let params = json!({ "server": "example.com", "uuid": TEXT, "password": "x" });
        assert!(JuicityFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_a_chain_fingerprint_together_with_a_skipped_check() {
        // Настройка обещала бы защиту, которой при `insecure` нет.
        let params = json!({
            "server": "example.com:443",
            "uuid": TEXT,
            "password": "x",
            "tls": { "insecure": true, "pinned_certchain_sha256": "ab".repeat(32) }
        });
        assert!(JuicityFactory::new().validate(&params).is_err());
    }

    #[test]
    fn protocol_name_is_stable() {
        assert_eq!(JuicityFactory::new().protocol(), "juicity");
    }
}
