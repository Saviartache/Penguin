//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL_HTTP2;
use crate::config::NaiveConfig;
use crate::outbound::NaiveHttp2Outbound;

/// Фабрика сервера naive.
#[derive(Debug, Clone, Copy)]
pub struct NaiveFactory;

impl NaiveFactory {
    /// `CONNECT` поверх HTTP/2.
    pub fn http2() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(&self, params: &serde_json::Value) -> Result<NaiveConfig, ProtocolError> {
        serde_json::from_value(params.clone())
            .map_err(|e| ProtocolError::InvalidConfig(format!("{}: {e}", self.protocol())))
    }
}

#[async_trait]
impl ProtocolFactory for NaiveFactory {
    fn protocol(&self) -> &'static str {
        PROTOCOL_HTTP2
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

        // В отличие от `http-proxy`, здесь соединение поднимается сразу и
        // держится открытым на весь профиль: у HTTP/2 есть
        // мультиплексирование, и повторное рукопожатие на каждый поток было
        // бы платой за то, ради чего этот протокол выбирают.
        Ok(Arc::new(
            NaiveHttp2Outbound::connect(ctx.id, config, ctx.dialer).await?,
        ))
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
        NaiveFactory::http2()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_address() {
        assert!(NaiveFactory::http2().validate(&json!({})).is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let params = json!({ "server": "example.com:443", "passwort": "y" });
        assert!(NaiveFactory::http2().validate(&params).is_err());
    }

    #[test]
    fn protocol_names_are_stable() {
        // Имя стоит в конфигурациях пользователей — менять его нельзя.
        assert_eq!(NaiveFactory::http2().protocol(), "http2");
    }
}
