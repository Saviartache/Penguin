//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL;
use crate::config::SshConfig;
use crate::outbound::SshOutbound;

/// Фабрика SSH.
#[derive(Debug, Default, Clone, Copy)]
pub struct SshFactory;

impl SshFactory {
    /// Создаёт фабрику.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<SshConfig, ProtocolError> {
        serde_json::from_value(params.clone())
            .map_err(|e| ProtocolError::InvalidConfig(format!("SSH: {e}")))
    }
}

#[async_trait]
impl ProtocolFactory for SshFactory {
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
        // Соединение здесь не поднимается: первый канал заводит первое.
        Ok(Arc::new(SshOutbound::new(ctx.id, config, ctx.dialer)?))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const FINGERPRINT: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";

    #[test]
    fn validates_a_good_config_with_a_password() {
        let params = json!({
            "server": "example.com:22",
            "username": "penguin",
            "password": "secret",
            "host_fingerprint": FINGERPRINT,
        });
        SshFactory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_config_with_neither_password_nor_key() {
        let params = json!({
            "server": "example.com:22",
            "username": "penguin",
            "host_fingerprint": FINGERPRINT,
        });
        assert!(SshFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_a_missing_host_fingerprint() {
        let params = json!({
            "server": "example.com:22",
            "username": "penguin",
            "password": "secret",
        });
        assert!(SshFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_address_without_a_port() {
        let params = json!({
            "server": "example.com",
            "username": "penguin",
            "password": "secret",
            "host_fingerprint": FINGERPRINT,
        });
        assert!(SshFactory::new().validate(&params).is_err());
    }

    #[test]
    fn protocol_name_is_stable() {
        assert_eq!(SshFactory::new().protocol(), "ssh");
    }
}
