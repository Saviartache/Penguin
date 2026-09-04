//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL;
use crate::config::VlessConfig;
use crate::outbound::VlessOutbound;

/// Фабрика VLESS.
#[derive(Debug, Default, Clone, Copy)]
pub struct VlessFactory;

impl VlessFactory {
    /// Создаёт фабрику.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<VlessConfig, ProtocolError> {
        serde_json::from_value(params.clone())
            .map_err(|e| ProtocolError::InvalidConfig(format!("VLESS: {e}")))
    }
}

#[async_trait]
impl ProtocolFactory for VlessFactory {
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
        let outbound = VlessOutbound::new(ctx.id, config, ctx.dialer)?;

        // Проверка доходит до сертификата и там останавливается: UUID сервер
        // не подтверждает и не отвергает. Без неё «Подключено» загоралось бы
        // и на сервере, которого нет.
        outbound.verify().await?;
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
        let params = json!({ "server": "example.com:443", "uuid": TEXT });
        VlessFactory::new()
            .validate(&params)
            .expect("настройки верны");

        let params = json!({
            "server": "example.com:443",
            "uuid": TEXT,
            "transport": "ws",
            "path": "/ws",
            "host": "cdn.example.com",
            "udp": false,
            "tls": { "sni": "cdn.example.com" }
        });
        VlessFactory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_uuid() {
        let params = json!({ "server": "example.com:443" });
        assert!(VlessFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_something_that_is_not_a_uuid() {
        // В это поле вставляют пароль — обычная ошибка.
        let params = json!({ "server": "example.com:443", "uuid": "пароль" });
        assert!(VlessFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_a_flow_we_cannot_keep() {
        let params = json!({
            "server": "example.com:443",
            "uuid": TEXT,
            "flow": "xtls-rprx-vision"
        });
        let err = VlessFactory::new().validate(&params).expect_err("не умеем");
        assert!(err.to_string().contains("xtls-rprx-vision"), "{err}");
    }

    #[test]
    fn rejects_an_address_without_a_port() {
        let params = json!({ "server": "example.com", "uuid": TEXT });
        assert!(VlessFactory::new().validate(&params).is_err());
    }

    #[test]
    fn protocol_name_is_stable() {
        assert_eq!(VlessFactory::new().protocol(), "vless");
    }
}
