//! Ошибки платформенного слоя.
//!
//! Здесь ломается то, что клиент делает **системе**: маршруты, брандмауэр,
//! служба. Почти всё это требует прав, и почти всё надо уметь откатить —
//! отсюда отдельный вариант для отката: не сумев вернуть систему в исходное
//! состояние, клиент обязан сказать об этом громко.

use thiserror::Error;

/// Результат платформенной операции.
pub type PlatformResult<T> = Result<T, PlatformError>;

/// Что не удалось сделать с системой.
#[derive(Debug, Error)]
pub enum PlatformError {
    /// Не хватает прав.
    #[error("нужны права администратора: {0}")]
    PermissionDenied(String),

    /// Не удалось поставить или снять маршрут.
    #[error("маршрут: {0}")]
    Route(String),

    /// Не удалось определить интерфейс.
    #[error("сетевой интерфейс: {0}")]
    Interface(String),

    /// Не удалось настроить брандмауэр.
    #[error("брандмауэр: {0}")]
    Firewall(String),

    /// Не удалось изменить настройки DNS.
    #[error("настройки DNS: {0}")]
    DnsSettings(String),

    /// Не удалось показать окно выбора файла.
    #[error("окно выбора файла: {0}")]
    Dialog(String),

    /// Не удалось управлять службой.
    #[error("служба: {0}")]
    Service(String),

    /// Не удалось вернуть систему в исходное состояние.
    ///
    /// Худшая из ошибок: маршруты или правила брандмауэра остались от
    /// клиента, которого уже нет, и сеть у пользователя может не работать
    /// вовсе. Молчать об этом нельзя ни при каких условиях.
    #[error("не удалось отменить изменение системы ({what}): {reason}")]
    RollbackFailed {
        /// Что осталось неотменённым.
        what: &'static str,
        /// Почему.
        reason: String,
    },

    /// Действие на этой платформе не поддерживается.
    #[error("на этой платформе не поддерживается: {0}")]
    Unsupported(&'static str),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl PlatformError {
    /// Ошибка отката.
    pub fn rollback(what: &'static str, reason: impl std::fmt::Display) -> Self {
        Self::RollbackFailed {
            what,
            reason: reason.to_string(),
        }
    }

    /// Нужны ли пользователю права, чтобы это исправить.
    pub fn needs_privileges(&self) -> bool {
        matches!(self, Self::PermissionDenied(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_failure_names_what_is_left_behind() {
        // Пользователь должен узнать, что именно осталось в системе: без
        // этого он не поймёт, почему сеть перестала работать.
        let err = PlatformError::rollback("маршрут по умолчанию", "отказано в доступе");
        let message = err.to_string();
        assert!(message.contains("маршрут по умолчанию"));
        assert!(message.contains("отказано в доступе"));
    }

    #[test]
    fn permission_errors_are_distinguishable() {
        assert!(PlatformError::PermissionDenied("маршрут".into()).needs_privileges());
        assert!(!PlatformError::Route("занят".into()).needs_privileges());
    }
}
