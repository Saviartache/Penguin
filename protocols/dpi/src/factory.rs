//! Регистрация режима: разбор настроек и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory, parse_params};
use penguin_proto::outbound::Outbound;

use crate::config::DpiConfig;
use crate::outbound::DpiOutbound;

/// Фабрика режима DPI.
#[derive(Debug, Default, Clone, Copy)]
pub struct DpiFactory;

impl DpiFactory {
    /// Новая фабрика.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(&self, params: &serde_json::Value) -> Result<DpiConfig, ProtocolError> {
        parse_params(self.protocol(), params)
    }
}

#[async_trait]
impl ProtocolFactory for DpiFactory {
    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn validate(&self, params: &serde_json::Value) -> Result<(), ProtocolError> {
        self.parse(params)?.validate().map_err(Into::into)
    }

    async fn build(
        &self,
        ctx: BuildContext,
        params: &serde_json::Value,
    ) -> Result<Arc<dyn Outbound>, ProtocolError> {
        // Подключаться некуда и не к кому: сервера у этого режима нет.
        // Поэтому здесь только разбор настроек — и «подключено» не врёт.
        let config = self.parse(params)?;
        Ok(Arc::new(DpiOutbound::new(ctx.id, &config, ctx.dialer)?))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn an_empty_profile_is_a_working_one() {
        // Настраивать в этом режиме нечего: без раздела он берёт свою
        // стратегию и работает.
        DpiFactory::new()
            .validate(&json!({}))
            .expect("настройки верны");
    }

    #[test]
    fn a_strategy_that_needs_a_decoy_is_refused_in_the_form() {
        // Ошибку показывает форма, а не молчание браузера через минуту.
        let err = DpiFactory::new()
            .validate(&json!({ "desync": { "strategy": "fake" } }))
            .expect_err("ложную посылку тут послать некому");
        assert!(err.to_string().contains("fake"));
    }

    #[test]
    fn the_protocol_name_is_stable() {
        // Имя стоит в конфигурациях пользователей — менять его нельзя.
        assert_eq!(DpiFactory::new().protocol(), "dpi");
    }
}
