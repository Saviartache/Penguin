//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory, parse_params};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL_MASQUE;
use crate::config::MasqueConfig;
use crate::outbound::MasqueOutbound;

/// Фабрика прокси MASQUE (`CONNECT-UDP`, RFC 9298).
#[derive(Debug, Clone, Copy, Default)]
pub struct MasqueFactory;

impl MasqueFactory {
    /// Заводит фабрику. Состояния у неё нет — она только разбирает параметры.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(&self, params: &serde_json::Value) -> Result<MasqueConfig, ProtocolError> {
        parse_params(self.protocol(), params)
    }
}

#[async_trait]
impl ProtocolFactory for MasqueFactory {
    fn protocol(&self) -> &'static str {
        PROTOCOL_MASQUE
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
        // у CONNECT-UDP есть мультиплексирование, и повторное рукопожатие на
        // каждую UDP-ассоциацию было бы платой за то, ради чего его выбирают.
        let outbound = MasqueOutbound::connect(ctx.id, config, ctx.dialer).await?;
        Ok(Arc::new(outbound))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn validates_a_good_config() {
        let params = json!({ "server": "example.com:443" });
        MasqueFactory.validate(&params).expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_address() {
        assert!(MasqueFactory.validate(&json!({})).is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let params = json!({ "server": "example.com:443", "passwort": "y" });
        assert!(MasqueFactory.validate(&params).is_err());
    }

    #[test]
    fn the_protocol_name_is_stable() {
        // Имя стоит в конфигурациях пользователей — менять его нельзя.
        assert_eq!(MasqueFactory.protocol(), "masque");
    }
}
