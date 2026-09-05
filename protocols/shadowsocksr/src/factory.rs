//! Регистрация протокола: разбор конфигурации и сборка направления.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL;
use crate::config::ShadowsocksrConfig;
use crate::outbound::ShadowsocksrOutbound;

/// Фабрика ShadowsocksR.
#[derive(Debug, Default, Clone, Copy)]
pub struct ShadowsocksrFactory;

impl ShadowsocksrFactory {
    /// Создаёт фабрику.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<ShadowsocksrConfig, ProtocolError> {
        serde_json::from_value(params.clone())
            .map_err(|e| ProtocolError::InvalidConfig(format!("ShadowsocksR: {e}")))
    }
}

#[async_trait]
impl ProtocolFactory for ShadowsocksrFactory {
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
        let outbound = ShadowsocksrOutbound::new(ctx.id, config, ctx.dialer)?;

        // Пробного подключения здесь нет по той же причине, что и у
        // Shadowsocks: серверу нечего ответить, пока не пришёл адрес
        // назначения, а слать его в никуда ради проверки — открывать
        // соединение, о котором никто не просил.
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
            "method": "aes-256-cfb",
            "password": "secret"
        });
        ShadowsocksrFactory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn validates_a_config_with_obfs_and_protocol() {
        let params = json!({
            "server": "example.com:8388",
            "method": "rc4-md5",
            "password": "secret",
            "obfs": "http_simple",
            "obfs_param": "cdn.example.net",
            "protocol_method": "auth_aes128_sha1"
        });
        ShadowsocksrFactory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_method() {
        let params = json!({ "server": "example.com:8388", "password": "secret" });
        assert!(ShadowsocksrFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_a_missing_password() {
        let params = json!({ "server": "example.com:8388", "method": "aes-256-cfb" });
        assert!(ShadowsocksrFactory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_unimplemented_protocol_by_name() {
        // `auth_chain_a` существует у эталона, но не реализован здесь —
        // отказ должен называть его, а не молчать про угаданное `origin`.
        let params = json!({
            "server": "example.com:8388",
            "method": "aes-256-cfb",
            "password": "secret",
            "protocol_method": "auth_chain_a"
        });
        let err = ShadowsocksrFactory::new()
            .validate(&params)
            .expect_err("не реализован");
        assert!(err.to_string().contains("auth_chain_a"), "{err}");
    }

    #[test]
    fn rejects_an_address_without_a_port() {
        let params = json!({
            "server": "example.com",
            "method": "aes-256-cfb",
            "password": "secret"
        });
        assert!(ShadowsocksrFactory::new().validate(&params).is_err());
    }

    #[test]
    fn protocol_name_is_stable() {
        // Имя стоит в конфигурациях пользователей — менять его нельзя.
        assert_eq!(ShadowsocksrFactory::new().protocol(), "shadowsocksr");
    }
}
