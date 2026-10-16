//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory, parse_params};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL;
use crate::config::ShadowsocksConfig;
use crate::outbound::ShadowsocksOutbound;

/// Фабрика Shadowsocks.
#[derive(Debug, Default, Clone, Copy)]
pub struct ShadowsocksFactory;

impl ShadowsocksFactory {
    /// Создаёт фабрику.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<ShadowsocksConfig, ProtocolError> {
        parse_params("Shadowsocks", params)
    }
}

#[async_trait]
impl ProtocolFactory for ShadowsocksFactory {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn validate(&self, params: &serde_json::Value) -> Result<(), ProtocolError> {
        Self::parse(params)?.validate().map_err(Into::into)
    }

    /// Пробного подключения нет: сервер молчит до адреса, неверный пароль виден на первом потоке.
    async fn build(
        &self,
        ctx: BuildContext,
        params: &serde_json::Value,
    ) -> Result<Arc<dyn Outbound>, ProtocolError> {
        let config = Self::parse(params)?;
        let outbound = ShadowsocksOutbound::new(ctx.id, config, ctx.dialer)?;
        Ok(Arc::new(outbound))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn validates_a_good_config() {
        let params = json!({
            "server": "example.com:8388",
            "method": "aes-256-gcm",
            "password": "secret"
        });
        ShadowsocksFactory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_method() {
        let params = json!({ "server": "example.com:8388", "password": "secret" });
        assert!(ShadowsocksFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_a_missing_password() {
        let params = json!({ "server": "example.com:8388", "method": "aes-256-gcm" });
        assert!(ShadowsocksFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_a_stream_cipher() {
        let params = json!({
            "server": "example.com:8388",
            "method": "aes-256-cfb",
            "password": "secret"
        });
        assert!(ShadowsocksFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_address_without_a_port() {
        let params = json!({
            "server": "example.com",
            "method": "aes-256-gcm",
            "password": "secret"
        });
        assert!(ShadowsocksFactory::new().validate(&params).is_err());
    }

    #[test]
    fn protocol_name_is_stable() {
        assert_eq!(ShadowsocksFactory::new().protocol(), "shadowsocks");
    }
}
