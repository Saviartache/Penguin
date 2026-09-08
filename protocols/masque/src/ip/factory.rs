//! Регистрация протокола `CONNECT-IP`: разбор конфигурации, согласование
//! адреса, сборка направления.
//!
//! В отличие от `CONNECT-UDP`, [`PacketFactory::build`] не может отложить
//! согласование до первого пакета — интерфейс с адресом, который обязана
//! вернуть [`interface`], нужен раньше первого же вызова `send`/`recv`.
//! Поэтому весь обмен — TLS, апгрейд, `ADDRESS_REQUEST`/`ADDRESS_ASSIGN` —
//! происходит прямо здесь, и `build` возвращает либо работающий тоннель,
//! либо ошибку, объясняющую, на каком шаге он не поднялся.
//!
//! [`interface`]: penguin_proto::packet::PacketOutbound::interface

use std::sync::Arc;

use async_trait::async_trait;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::{BuildContext, parse_params};
use penguin_proto::packet::{PacketFactory, PacketOutbound};

use super::PROTOCOL_MASQUE_IP;
use super::outbound::MasqueIpOutbound;
use crate::config::MasqueConfig;

/// Фабрика направления `CONNECT-IP` (RFC 9484).
#[derive(Debug, Clone, Copy, Default)]
pub struct MasqueIpFactory;

impl MasqueIpFactory {
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
impl PacketFactory for MasqueIpFactory {
    fn protocol(&self) -> &'static str {
        PROTOCOL_MASQUE_IP
    }

    fn validate(&self, params: &serde_json::Value) -> Result<(), ProtocolError> {
        // Проверка без сети: интерфейс должен показать ошибку в поле сразу,
        // а не через минуту неудачного согласования.
        self.parse(params)?.validate().map_err(Into::into)
    }

    async fn build(
        &self,
        ctx: BuildContext,
        params: &serde_json::Value,
    ) -> Result<Arc<dyn PacketOutbound>, ProtocolError> {
        let config = self.parse(params)?;
        let outbound = MasqueIpOutbound::connect(ctx.id, config, ctx.dialer).await?;
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
        MasqueIpFactory.validate(&params).expect("настройки верны");
    }

    #[test]
    fn rejects_a_missing_address() {
        assert!(MasqueIpFactory.validate(&json!({})).is_err());
    }

    #[test]
    fn rejects_an_unknown_field() {
        let params = json!({ "server": "example.com:443", "passwort": "y" });
        assert!(MasqueIpFactory.validate(&params).is_err());
    }

    #[test]
    fn the_protocol_name_is_stable() {
        // Имя стоит в конфигурациях пользователей — менять его нельзя.
        assert_eq!(MasqueIpFactory.protocol(), "masque-ip");
    }
}
