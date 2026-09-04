//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL;
use crate::config::AnyTlsConfig;
use crate::outbound::AnyTlsOutbound;

/// Фабрика AnyTLS.
#[derive(Debug, Default, Clone, Copy)]
pub struct AnyTlsFactory;

impl AnyTlsFactory {
    /// Создаёт фабрику.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<AnyTlsConfig, ProtocolError> {
        serde_json::from_value(params.clone())
            .map_err(|e| ProtocolError::InvalidConfig(format!("AnyTLS: {e}")))
    }
}

#[async_trait]
impl ProtocolFactory for AnyTlsFactory {
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
        // Соединение здесь не поднимается: первая сессия заводится первым
        // потоком. Включённый профиль не обязан держать соединение TLS.
        Ok(Arc::new(AnyTlsOutbound::new(ctx.id, config, ctx.dialer)?))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn validates_a_good_config() {
        let params = json!({ "server": "example.com:443", "password": "secret" });
        AnyTlsFactory::new()
            .validate(&params)
            .expect("настройки верны");

        let params = json!({
            "server": "example.com:8443",
            "password": "secret",
            "client": "",
            "idle_check_secs": 60,
            "idle_timeout_secs": 120,
            "min_idle_sessions": 2,
            "udp": false,
            "tls": { "sni": "cdn.example.com", "insecure": true }
        });
        AnyTlsFactory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_password() {
        let params = json!({ "server": "example.com:443" });
        assert!(AnyTlsFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_address_without_a_port() {
        let params = json!({ "server": "example.com", "password": "x" });
        assert!(AnyTlsFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_a_fingerprint_together_with_a_skipped_check() {
        // Настройка обещала бы защиту, которой при `insecure` нет.
        let params = json!({
            "server": "example.com:443",
            "password": "x",
            "tls": { "insecure": true, "pin_sha256": "00".repeat(32) }
        });
        assert!(AnyTlsFactory::new().validate(&params).is_err());
    }

    #[test]
    fn protocol_name_is_stable() {
        assert_eq!(AnyTlsFactory::new().protocol(), "anytls");
    }
}
