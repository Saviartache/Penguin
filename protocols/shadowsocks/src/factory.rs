//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory};
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
        serde_json::from_value(params.clone())
            .map_err(|e| ProtocolError::InvalidConfig(format!("Shadowsocks: {e}")))
    }
}

#[async_trait]
impl ProtocolFactory for ShadowsocksFactory {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn validate(&self, params: &serde_json::Value) -> Result<(), ProtocolError> {
        // Проверка без сети: интерфейс должен показать ошибку в поле сразу,
        // а не через минуту неудачного подключения.
        Self::parse(params)?.validate().map_err(Into::into)
    }

    async fn build(
        &self,
        ctx: BuildContext,
        params: &serde_json::Value,
    ) -> Result<Arc<dyn Outbound>, ProtocolError> {
        let config = Self::parse(params)?;
        let outbound = ShadowsocksOutbound::new(ctx.id, config, ctx.dialer)?;

        // Пробного подключения здесь нет, и это не пропуск. Проверять было бы
        // нечего: сервер не отвечает на соединение ничем, пока ему не пришлют
        // адрес назначения, а слать его в никуда ради проверки — значит
        // открывать соединение, о котором никто не просил. Неверный пароль
        // выясняется на первом же потоке и приходит как `AuthRejected`.
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
        // Угадать метод нельзя: подставленный молча даёт соединение, которое
        // открывается и ничего не передаёт.
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
        // Он не заверяет данные: правку по дороге не заметит никто.
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
        // Имя стоит в конфигурациях пользователей — менять его нельзя.
        assert_eq!(ShadowsocksFactory::new().protocol(), "shadowsocks");
    }
}
