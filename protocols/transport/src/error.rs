//! Ошибки транспорта.
//!
//! Своё перечисление, а не общий [`ProtocolError`], по той же причине, по
//! которой оно есть у каждого протокола: транспорт различает вещи, которых
//! общий язык не знает, — «сервер ответил не по WebSocket» и «сервер не
//! ответил вовсе» выглядят выше по стеку одинаково, а лечатся по-разному.
//!
//! Обратно в общий язык оно переводится здесь же, и перевод закрепляет
//! обещание про повторные попытки (`AGENTS.md` §4.2): всё, что само собой не
//! изменится, попадает в невосстановимые варианты.

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

    /// Собеседник ответил не по протоколу.
    ///
    /// Чаще всего это значит, что на том конце не то, что настроено: обычный
    /// сайт вместо прокси, HTTP вместо WebSocket.
    #[error("ответ не по протоколу: {0}")]
    Malformed(String),

    /// Рукопожатие не уложилось в срок.
    ///
    /// Отдельный вариант, а не `Io(TimedOut)`: молчащий сервер — это повод
    /// повторить попытку, и `supervisor` должен это видеть.
    #[error("{0} не уложилось в срок")]
    Timeout(&'static str),

    /// Метка подлинности не сошлась.
    ///
    /// Для AEAD это не «шум на линии»: метка заверяет данные, и не сошедшаяся
    /// означает либо неверный пароль, либо правку по дороге. Различить их
    /// нельзя, и продолжать нельзя ни в том, ни в другом случае.
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
            // Не по протоколу — это ошибка настроек, а не сети: пока в поле
            // стоит адрес не того сервера, повторять нечего.
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
        // Молчащий сервер — это сеть, а не настройки: повторять обязательно.
        let err: ProtocolError = TransportError::Timeout("рукопожатие TLS").into();
        assert!(err.is_retryable());
        assert!(err.to_string().contains("рукопожатие TLS"));
    }

    #[test]
    fn the_wrong_kind_of_server_is_not_retried() {
        // На порту сидит не то, что настроено. Само оно не поменяется.
        let err: ProtocolError = TransportError::malformed("HTTP/1.1 200 вместо 101").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_broken_config_is_not_retried() {
        let err: ProtocolError = TransportError::config("пустой SNI").into();
        assert!(!err.is_retryable());
    }
}
