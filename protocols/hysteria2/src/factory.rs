//! Регистрация протокола: разбор конфигурации и сборка клиента.
//!
//! Единственная точка, которой протокол показывается наружу. Всё остальное в
//! крейте — подробности, до которых клиенту дела нет.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL;
use crate::client::Hysteria2Client;
use crate::config::Hysteria2Config;

/// Фабрика Hysteria 2.
#[derive(Debug, Default, Clone, Copy)]
pub struct Hysteria2Factory;

impl Hysteria2Factory {
    /// Создаёт фабрику.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<Hysteria2Config, ProtocolError> {
        serde_json::from_value(params.clone())
            .map_err(|e| ProtocolError::InvalidConfig(format!("Hysteria 2: {e}")))
    }
}

#[async_trait]
impl ProtocolFactory for Hysteria2Factory {
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
        let client = Hysteria2Client::connect(ctx.id, &config, ctx.dialer).await?;
        Ok(Arc::new(client))
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
            "auth": "hunter2",
            "bandwidth": { "up": "100 mbps", "down": "200 mbps" }
        });
        Hysteria2Factory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_missing_password() {
        let params = json!({ "server": "example.com:443" });
        assert!(Hysteria2Factory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_unknown_field() {
        // Опечатка в имени поля не должна молча превращаться в умолчание:
        // пользователь напишет `passwort` и будет гадать, почему не работает.
        let params = json!({ "server": "example.com:443", "auth": "x", "passwort": "y" });
        assert!(Hysteria2Factory::new().validate(&params).is_err());
    }

    #[test]
    fn accepts_an_ip_server_without_sni() {
        // Такие ссылки раздают как есть: `hy2://пароль@203.0.113.5:1984/?insecure=1`.
        // Имя для TLS тогда не нужно — SNI в рукопожатие просто не попадает.
        let params = json!({
            "server": "203.0.113.5:1984",
            "auth": "x",
            "tls": { "insecure": true }
        });
        Hysteria2Factory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn protocol_name_is_stable() {
        // Имя стоит в конфигурациях пользователей — менять его нельзя.
        assert_eq!(Hysteria2Factory::new().protocol(), "hysteria2");
    }
}
