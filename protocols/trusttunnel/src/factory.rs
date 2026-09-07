//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory, parse_params};
use penguin_proto::outbound::Outbound;

use crate::config::TrustTunnelConfig;
use crate::outbound::TrustTunnelOutbound;

/// Фабрика сервера TrustTunnel.
#[derive(Debug, Default, Clone, Copy)]
pub struct TrustTunnelFactory;

impl TrustTunnelFactory {
    /// Новая фабрика.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(&self, params: &serde_json::Value) -> Result<TrustTunnelConfig, ProtocolError> {
        parse_params(self.protocol(), params)
    }
}

#[async_trait]
impl ProtocolFactory for TrustTunnelFactory {
    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn validate(&self, params: &serde_json::Value) -> Result<(), ProtocolError> {
        // Проверка без сети: интерфейс должен показать ошибку в поле сразу,
        // а не через минуту неудачного подключения.
        self.parse(params)?.validate().map_err(Into::into)
    }

    async fn build(
        &self,
        ctx: BuildContext,
        params: &serde_json::Value,
    ) -> Result<Arc<dyn Outbound>, ProtocolError> {
        let config = self.parse(params)?;
        // Соединение поднимается сразу и держится открытым на весь профиль:
        // у HTTP/2 есть мультиплексирование, и поднимать TLS заново на
        // каждый поток значило бы платить за то, ради чего он выбран.
        let outbound = TrustTunnelOutbound::connect(ctx.id, config, ctx.dialer).await?;
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
            "server": "example.com:443",
            "username": "penguin",
            "password": "secret",
        });
        TrustTunnelFactory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_address() {
        assert!(TrustTunnelFactory::new().validate(&json!({})).is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let params = json!({
            "server": "example.com:443",
            "username": "penguin",
            "password": "secret",
            "passwort": "y",
        });
        assert!(TrustTunnelFactory::new().validate(&params).is_err());
    }

    #[test]
    fn the_protocol_name_is_stable() {
        // Имя стоит в конфигурациях пользователей — менять его нельзя.
        assert_eq!(TrustTunnelFactory::new().protocol(), "trusttunnel");
    }
}
