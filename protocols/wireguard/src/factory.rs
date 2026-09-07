//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, parse_params};
use penguin_proto::packet::{PacketFactory, PacketOutbound};

use crate::PROTOCOL;
use crate::config::WireguardConfig;
use crate::outbound::WireguardOutbound;

/// Фабрика WireGuard.
#[derive(Debug, Default, Clone, Copy)]
pub struct WireguardFactory;

impl WireguardFactory {
    /// Создаёт фабрику.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<WireguardConfig, ProtocolError> {
        parse_params("WireGuard", params)
    }
}

#[async_trait]
impl PacketFactory for WireguardFactory {
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
    ) -> Result<Arc<dyn PacketOutbound>, ProtocolError> {
        let config = Self::parse(params)?;
        config.validate()?;
        let outbound = WireguardOutbound::connect(ctx.id, config, ctx.dialer).await?;
        Ok(Arc::new(outbound))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const ZERO_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn validates_a_good_config() {
        let params = json!({
            "server": "vpn.example.com:51820",
            "private_key": ZERO_KEY,
            "server_public_key": ZERO_KEY,
            "address_ipv4": "10.0.0.2/32",
        });
        WireguardFactory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_interface_address() {
        let params = json!({
            "server": "vpn.example.com:51820",
            "private_key": ZERO_KEY,
            "server_public_key": ZERO_KEY,
        });
        assert!(WireguardFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_a_key_that_is_not_base64() {
        let params = json!({
            "server": "vpn.example.com:51820",
            "private_key": "не base64!",
            "server_public_key": ZERO_KEY,
            "address_ipv4": "10.0.0.2/32",
        });
        assert!(WireguardFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let params = json!({
            "server": "vpn.example.com:51820",
            "private_key": ZERO_KEY,
            "server_public_key": ZERO_KEY,
            "address_ipv4": "10.0.0.2/32",
            "presharred_key": "опечатка",
        });
        assert!(WireguardFactory::new().validate(&params).is_err());
    }

    #[test]
    fn protocol_name_is_stable() {
        assert_eq!(WireguardFactory::new().protocol(), PROTOCOL);
        assert_eq!(PROTOCOL, "wireguard");
    }
}
