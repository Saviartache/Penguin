//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory, parse_params};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL;
use crate::config::I2pConfig;
use crate::outbound::I2pOutbound;

/// Фабрика направления I2P.
#[derive(Debug, Default, Clone, Copy)]
pub struct I2pFactory;

impl I2pFactory {
    /// Новая фабрика.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProtocolFactory for I2pFactory {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn validate(&self, params: &serde_json::Value) -> Result<(), ProtocolError> {
        parse_params::<I2pConfig>("I2P", params)?
            .validate()
            .map_err(Into::into)
    }

    /// Проверяет только i2pd: пробный поток через I2P на первом запуске шёл бы минутами.
    async fn build(
        &self,
        ctx: BuildContext,
        params: &serde_json::Value,
    ) -> Result<Arc<dyn Outbound>, ProtocolError> {
        let config: I2pConfig = parse_params("I2P", params)?;
        let outbound = I2pOutbound::new(ctx.id, &config, ctx.dialer)?;
        outbound.verify().await?;
        Ok(Arc::new(outbound))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn validates_the_defaults_and_refuses_a_bad_outproxy() {
        I2pFactory::new().validate(&json!({})).expect("умолчания");
        assert!(
            I2pFactory::new()
                .validate(&json!({ "outproxy": "http://example.com" }))
                .is_err()
        );
    }

    #[test]
    fn protocol_name_is_stable() {
        assert_eq!(I2pFactory::new().protocol(), "i2p");
    }
}
