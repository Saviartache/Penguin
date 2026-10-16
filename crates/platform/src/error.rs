//! Ошибки платформенного слоя; отдельный вариант — для неудавшегося отката.

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

    /// Такой маршрут уже стоит.
    #[error("маршрут уже стоит")]
    RouteExists,

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

    /// Не удалось вернуть систему в исходное состояние: сеть может не работать вовсе.
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
