//! `ProtocolFactory` — разбор параметров и сборка `Outbound` из конфигурации.

use std::sync::Arc;

use async_trait::async_trait;
use penguin_core::id::OutboundId;

use crate::dialer::Dialer;
use crate::error::ProtocolError;
use crate::outbound::Outbound;

/// Всё, что нужно фабрике, кроме её собственных параметров.
///
/// Отдельная структура вместо длинного списка аргументов: добавление
/// зависимости не будет ломать сигнатуру у всех протоколов сразу.
pub struct BuildContext {
    /// Идентификатор, который получит собранное направление.
    pub id: OutboundId,
    /// Выход наружу мимо тоннеля.
    pub dialer: Arc<dyn Dialer>,
}

/// Фабрика протокола.
///
/// Ровно одна на протокол; регистрируется в [`crate::registry::ProtocolRegistry`].
/// Параметры приходят непрозрачным JSON: `penguin-config` не знает схемы
/// протоколов, иначе каждый новый протокол правил бы общий конфиг.
#[async_trait]
pub trait ProtocolFactory: Send + Sync + 'static {
    /// Имя протокола в конфигурации: `"hysteria2"`.
    fn protocol(&self) -> &'static str;

    /// Проверяет параметры, не создавая соединения.
    ///
    /// Нужно интерфейсу: ошибку в поле надо показать в форме, а не через
    /// минуту неудачного подключения.
    fn validate(&self, params: &serde_json::Value) -> Result<(), ProtocolError>;

    /// Собирает направление и устанавливает соединение с сервером.
    async fn build(
        &self,
        ctx: BuildContext,
        params: &serde_json::Value,
    ) -> Result<Arc<dyn Outbound>, ProtocolError>;
}
