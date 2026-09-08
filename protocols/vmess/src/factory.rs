//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory, parse_params};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL;
use crate::config::VmessConfig;
use crate::outbound::VmessOutbound;

/// Фабрика VMess.
#[derive(Debug, Default, Clone, Copy)]
pub struct VmessFactory;

impl VmessFactory {
    /// Создаёт фабрику.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<VmessConfig, ProtocolError> {
        parse_params("VMess", params)
    }
}

#[async_trait]
impl ProtocolFactory for VmessFactory {
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
        let outbound = VmessOutbound::new(ctx.id, config, ctx.dialer)?;

        // Проверка доходит до сертификата (или до открытого TCP при
        // `security = "none"`) и там останавливается: идентичность сервер не
        // подтверждает и не отвергает без заголовка. Без неё «Подключено»
        // загоралось бы и на сервере, которого нет.
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
        let params = json!({ "server": "example.com:443", "id": TEXT });
        VmessFactory::new()
            .validate(&params)
            .expect("настройки верны");

        let params = json!({
            "server": "example.com:443",
            "id": TEXT,
            "transport": "ws",
            "path": "/ws",
            "host": "cdn.example.com",
            "udp": false,
            "cipher": "chacha20-poly1305",
            "tls": { "sni": "cdn.example.com" }
        });
        VmessFactory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_id() {
        let params = json!({ "server": "example.com:443" });
        assert!(VmessFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_a_nonzero_alter_id() {
        let params = json!({ "server": "example.com:443", "id": TEXT, "alter_id": 16 });
        let err = VmessFactory::new()
            .validate(&params)
            .expect_err("старый режим не поддержан");
        assert!(err.to_string().contains("alterId"), "{err}");
    }

    #[test]
    fn rejects_an_address_without_a_port() {
        let params = json!({ "server": "example.com", "id": TEXT });
        assert!(VmessFactory::new().validate(&params).is_err());
    }

    #[test]
    fn protocol_name_is_stable() {
        assert_eq!(VmessFactory::new().protocol(), "vmess");
    }
}
