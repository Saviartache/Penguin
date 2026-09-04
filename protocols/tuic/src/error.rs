//! Ошибки протокола.

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type TuicResult<T> = Result<T, TuicError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum TuicError {
    /// Настройки неверны или противоречивы.
    #[error("настройки TUIC: {0}")]
    Config(String),

    /// Адрес не укладывается в запись протокола.
    #[error("адрес не помещается в команду: {0}")]
    Address(String),

    /// Сервер прислал не то, что позволяет протокол.
    #[error("поток не по протоколу: {0}")]
    Malformed(String),

    /// Сервер закрыл соединение, не приняв проверку подлинности.
    ///
    /// Ответа на неё у TUIC нет: сервер, не сошедшийся отпечатком, просто
    /// закрывает соединение. Различить это от обрыва можно лишь по коду
    /// закрытия QUIC — и там, где он это позволяет, ошибка приходит сюда.
    #[error("сервер отклонил UUID или пароль")]
    Rejected,

    /// Соединение оборвалось.
    #[error("соединение потеряно: {0}")]
    Disconnected(String),

    /// Ошибка общего транспорта: TLS, срок рукопожатия.
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl TuicError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Адрес не помещается.
    pub fn address(message: impl Into<String>) -> Self {
        Self::Address(message.into())
    }

    /// Сервер прислал не то.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }
}

impl From<TuicError> for ProtocolError {
    fn from(err: TuicError) -> Self {
        match err {
            TuicError::Config(message) => Self::InvalidConfig(message),
            TuicError::Address(message) => Self::InvalidConfig(message),
            err @ TuicError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            // Неверный пароль повторять бессмысленно: он не изменится сам.
            TuicError::Rejected => Self::AuthRejected,
            TuicError::Disconnected(message) => Self::Disconnected(message),
            TuicError::Transport(err) => err.into(),
            TuicError::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rejected_password_is_not_retried() {
        let err: ProtocolError = TuicError::Rejected.into();
        assert!(!err.is_retryable());
        assert!(matches!(err, ProtocolError::AuthRejected));
    }

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = TuicError::Disconnected("сеть пропала".into()).into();
        assert!(err.is_retryable());
    }

    #[test]
    fn the_wrong_kind_of_server_is_not_retried() {
        let err: ProtocolError = TuicError::malformed("версия 0x04").into();
        assert!(!err.is_retryable());
    }
}
