//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL;
use crate::config::TuicConfig;
use crate::outbound::TuicOutbound;

/// Фабрика TUIC.
#[derive(Debug, Default, Clone, Copy)]
pub struct TuicFactory;

impl TuicFactory {
    /// Создаёт фабрику.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<TuicConfig, ProtocolError> {
        serde_json::from_value(params.clone())
            .map_err(|e| ProtocolError::InvalidConfig(format!("TUIC: {e}")))
    }
}

#[async_trait]
impl ProtocolFactory for TuicFactory {
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

        // Соединение поднимается здесь, а не при первом потоке: у TUIC оно
        // постоянное, и рукопожатие QUIC с проверкой подлинности платятся
        // один раз на весь профиль.
        let outbound = TuicOutbound::connect(ctx.id, config, ctx.dialer).await?;
        Ok(Arc::new(outbound))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn validates_a_good_config() {
        let params = json!({
            "server": "example.com:443",
            "uuid": TEXT,
            "password": "secret"
        });
        TuicFactory::new()
            .validate(&params)
            .expect("настройки верны");

        let params = json!({
            "server": "example.com:443",
            "uuid": TEXT,
            "password": "secret",
            "congestion": "cubic",
            "udp_mode": "quic",
            "udp": false,
            "tls": { "sni": "cdn.example.com", "insecure": true }
        });
        TuicFactory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_password() {
        let params = json!({ "server": "example.com:443", "uuid": TEXT });
        assert!(TuicFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_something_that_is_not_a_uuid() {
        let params = json!({
            "server": "example.com:443",
            "uuid": "пароль",
            "password": "secret"
        });
        assert!(TuicFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_unknown_congestion_controller() {
        // Опечатка не должна молча превращаться в умолчание: разница между
        // ними видна только под нагрузкой, и искать её будут в сети.
        let params = json!({
            "server": "example.com:443",
            "uuid": TEXT,
            "password": "secret",
            "congestion": "reno"
        });
        assert!(TuicFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_address_without_a_port() {
        let params = json!({ "server": "example.com", "uuid": TEXT, "password": "x" });
        assert!(TuicFactory::new().validate(&params).is_err());
    }

    #[test]
    fn protocol_name_is_stable() {
        assert_eq!(TuicFactory::new().protocol(), "tuic");
    }
}
