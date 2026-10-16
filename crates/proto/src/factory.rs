//! `ProtocolFactory` — разбор параметров и сборка `Outbound` из конфигурации.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_core::id::OutboundId;
use serde::de::DeserializeOwned;

use crate::dialer::Dialer;
use crate::error::ProtocolError;
use crate::outbound::Outbound;

/// Разбирает параметры протокола без копии `Value`; `name` — имя для человека («Hysteria 2»).
pub fn parse_params<T: DeserializeOwned>(
    name: &str,
    params: &serde_json::Value,
) -> Result<T, ProtocolError> {
    T::deserialize(params).map_err(|err| ProtocolError::InvalidConfig(format!("{name}: {err}")))
}

/// Всё, что нужно фабрике, кроме её параметров.
pub struct BuildContext {
    /// Идентификатор, который получит собранное направление.
    pub id: OutboundId,
    /// Выход наружу мимо тоннеля.
    pub dialer: Arc<dyn Dialer>,
}

/// Фабрика протокола, одна на протокол; параметры приходят непрозрачным JSON.
#[async_trait]
pub trait ProtocolFactory: Send + Sync + 'static {
    /// Имя протокола в конфигурации: `"hysteria2"`.
    fn protocol(&self) -> &'static str;

    /// Проверяет параметры, не создавая соединения.
    fn validate(&self, params: &serde_json::Value) -> Result<(), ProtocolError>;

    /// Собирает направление и устанавливает соединение с сервером.
    async fn build(
        &self,
        ctx: BuildContext,
        params: &serde_json::Value,
    ) -> Result<Arc<dyn Outbound>, ProtocolError>;
}
