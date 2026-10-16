//! Ошибки транспорта.
//!
//! Перевод в [`ProtocolError`] задаёт повторяемость (`AGENTS.md` §4.2).

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции транспорта.
pub type TransportResult<T> = Result<T, TransportError>;

/// Что пошло не так в транспорте.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Настройки транспорта неверны или противоречивы.
    #[error("настройки транспорта: {0}")]
    Config(String),

    /// Адрес не укладывается в формат, которым его надо записать.
    #[error("адрес не помещается в запрос: {0}")]
    Address(String),

    /// Собеседник ответил не по протоколу (на порту не тот сервер).
    #[error("ответ не по протоколу: {0}")]
    Malformed(String),

    /// Рукопожатие не уложилось в срок (повторяемо).
    #[error("{0} не уложилось в срок")]
    Timeout(&'static str),

    /// Метка AEAD не сошлась: неверный пароль или правка по дороге.
    #[error("метка подлинности не сошлась: неверный пароль или правка по дороге")]
    Rejected,

    /// Соединение оборвалось.
    #[error("соединение потеряно: {0}")]
    Disconnected(String),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl TransportError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Собеседник ответил не по протоколу.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }

    /// Адрес не помещается в запрос.
    pub fn address(message: impl Into<String>) -> Self {
        Self::Address(message.into())
    }

    /// Обрыв соединения.
    pub fn disconnected(message: impl Into<String>) -> Self {
        Self::Disconnected(message.into())
    }
}

impl From<TransportError> for ProtocolError {
    fn from(err: TransportError) -> Self {
        match err {
            TransportError::Config(message) => Self::InvalidConfig(message),
            TransportError::Address(message) => Self::InvalidConfig(message),
            err @ TransportError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            err @ TransportError::Timeout(_) => Self::Disconnected(err.to_string()),
            TransportError::Rejected => Self::AuthRejected,
            TransportError::Disconnected(message) => Self::Disconnected(message),
            TransportError::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_silent_server_is_retried() {
        let err: ProtocolError = TransportError::Timeout("рукопожатие TLS").into();
        assert!(err.is_retryable());
        assert!(err.to_string().contains("рукопожатие TLS"));
    }

    #[test]
    fn the_wrong_kind_of_server_is_not_retried() {
        let err: ProtocolError = TransportError::malformed("HTTP/1.1 200 вместо 101").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_broken_config_is_not_retried() {
        let err: ProtocolError = TransportError::config("пустой SNI").into();
        assert!(!err.is_retryable());
    }
}
