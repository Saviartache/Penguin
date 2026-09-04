//! Регистрация протокола: разбор конфигурации и сборка направления.
//!
//! Единственная точка, которой протокол показывается наружу. Всё остальное в
//! крейте — подробности, до которых клиенту дела нет.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, ProtocolFactory};
use penguin_proto::outbound::Outbound;

use crate::PROTOCOL;
use crate::config::Socks5Config;
use crate::outbound::Socks5Outbound;

/// Фабрика SOCKS5.
#[derive(Debug, Default, Clone, Copy)]
pub struct Socks5Factory;

impl Socks5Factory {
    /// Создаёт фабрику.
    pub fn new() -> Self {
        Self
    }

    /// Разбирает параметры из конфигурации.
    fn parse(params: &serde_json::Value) -> Result<Socks5Config, ProtocolError> {
        serde_json::from_value(params.clone())
            .map_err(|e| ProtocolError::InvalidConfig(format!("SOCKS5: {e}")))
    }
}

#[async_trait]
impl ProtocolFactory for Socks5Factory {
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
        let outbound = Socks5Outbound::new(ctx.id, config, ctx.dialer)?;

        // Пробное соединение при подъёме направления. Без него «Подключено»
        // загоралось бы и на прокси, которого нет: постоянного соединения у
        // SOCKS5 не бывает, и неверный пароль выяснился бы только на первом
        // потоке приложения — то есть выглядел бы сломанной страницей, а не
        // ошибкой профиля.
        outbound.verify().await?;
        Ok(Arc::new(outbound))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn validates_a_good_config() {
        let params = json!({ "server": "127.0.0.1:1080" });
        Socks5Factory::new()
            .validate(&params)
            .expect("настройки верны");

        let params = json!({
            "server": "proxy.example.com:1080",
            "username": "penguin",
            "password": "secret",
            "udp": false
        });
        Socks5Factory::new()
            .validate(&params)
            .expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_address() {
        assert!(Socks5Factory::new().validate(&json!({})).is_err());
    }

    #[test]
    fn rejects_an_address_without_a_port() {
        // Порт по умолчанию у SOCKS5 не определён: 1080 — обычай, а не правило,
        // и молча подставить его значит подключаться не туда.
        let params = json!({ "server": "127.0.0.1" });
        assert!(Socks5Factory::new().validate(&params).is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        // Опечатка в имени поля не должна молча превращаться в умолчание.
        let params = json!({ "server": "127.0.0.1:1080", "passwort": "y" });
        assert!(Socks5Factory::new().validate(&params).is_err());
    }

    #[test]
    fn protocol_name_is_stable() {
        // Имя стоит в конфигурациях пользователей — менять его нельзя.
        assert_eq!(Socks5Factory::new().protocol(), "socks5");
    }
}
