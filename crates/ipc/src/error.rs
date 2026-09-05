//! Ошибки канала управления.
//!
//! Две из них пользователь видит чаще всех остальных вместе взятых: демон не
//! запущен и доступ запрещён. Обе лечатся конкретным действием, поэтому у них
//! отдельные варианты с готовым текстом — «файл не найден» в ответ на попытку
//! подключиться никому ничего не объясняет.

use thiserror::Error;

/// Результат работы с каналом управления.
pub type IpcResult<T> = Result<T, IpcError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum IpcError {
    /// Демон не запущен.
    #[error("служба Penguin не запущена; запустите её командой `penguin service start`")]
    DaemonNotRunning,

    /// Демон уже работает.
    ///
    /// Возникает при попытке запустить второй экземпляр: канал управления
    /// один на систему.
    #[error("служба Penguin уже работает")]
    AlreadyRunning,

    /// Служба приняла запрос, но не ответила вовремя.
    ///
    /// Отдельно от [`Self::DaemonNotRunning`]: там службы нет и надо её
    /// запустить, здесь она есть и совет «запустите её» только запутает.
    #[error("служба Penguin не ответила вовремя; посмотрите её журнал")]
    NoAnswer,

    /// Доступ к каналу запрещён.
    #[error("нет доступа к каналу управления: запустите интерфейс от того же пользователя")]
    AccessDenied,

    /// The Unix controller approval is invalid or stored unsafely.
    #[error("invalid controller authorization: {0}")]
    InvalidController(&'static str),

    /// Сообщение не помещается в отведённый предел.
    #[error("сообщение длиной {size} байт превышает предел {limit}")]
    TooLarge {
        /// Сколько получилось.
        size: usize,
        /// Сколько можно.
        limit: usize,
    },

    /// Сообщение не разбирается.
    #[error("сообщение не разбирается: {0}")]
    Malformed(String),

    /// Демон ответил не тем.
    ///
    /// Почти всегда означает разные версии по разные стороны канала: служба
    /// осталась старой после обновления интерфейса.
    #[error("неожиданный ответ демона: {0}")]
    UnexpectedResponse(String),

    /// Ошибка транспорта.
    #[error("канал управления: {0}")]
    Transport(String),

    /// Ошибка разбора JSON.
    #[error("разбор сообщения: {0}")]
    Json(#[from] serde_json::Error),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl IpcError {
    /// Нужно ли пользователю что-то сделать.
    pub fn needs_user_action(&self) -> bool {
        matches!(
            self,
            Self::DaemonNotRunning
                | Self::AccessDenied
                | Self::AlreadyRunning
                | Self::InvalidController(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_daemon_tells_what_to_do() {
        let message = IpcError::DaemonNotRunning.to_string();
        assert!(
            message.contains("service start"),
            "не сказано, что делать: {message}"
        );
    }

    #[test]
    fn access_denied_explains_the_cause() {
        let message = IpcError::AccessDenied.to_string();
        assert!(
            message.contains("пользователя"),
            "причина невнятна: {message}"
        );
    }

    #[test]
    fn user_fixable_errors_are_marked() {
        assert!(IpcError::DaemonNotRunning.needs_user_action());
        assert!(!IpcError::Malformed("мусор".into()).needs_user_action());
    }
}
