//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку (`AGENTS.md` §4.2).
//!
//! Отказа по учётным данным у VLESS нет, как и у Trojan: сервер, не узнавший
//! UUID, закрывает соединение молча. Разница лишь в том, что заголовок ответа
//! у VLESS всё-таки есть, и его отсутствие видно сразу — приходит это как
//! `Disconnected`, то есть повторяемая ошибка. Отличить «не тот UUID» от
//! «сервер перезапускается» клиенту нечем.

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type VlessResult<T> = Result<T, VlessError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum VlessError {
    /// Настройки неверны или противоречивы.
    #[error("настройки VLESS: {0}")]
    Config(String),

    /// Сервер ответил не по протоколу.
    #[error("ответ не по протоколу: {0}")]
    Malformed(String),

    /// Датаграмма не помещается в объявляемую длину.
    #[error("датаграмма в {0} байт: длина пишется двумя байтами")]
    Oversized(usize),

    /// Проксирование UDP выключено в настройках профиля.
    #[error("проксирование UDP выключено в настройках профиля")]
    UdpDisabled,

    /// Соединение оборвалось.
    #[error("соединение потеряно: {0}")]
    Disconnected(String),

    /// Ошибка общего транспорта: TLS, WebSocket, срок рукопожатия, адрес.
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl VlessError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Сервер ответил не по протоколу.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }
}

impl From<VlessError> for ProtocolError {
    fn from(err: VlessError) -> Self {
        match err {
            VlessError::Config(message) => Self::InvalidConfig(message),
            // Не по протоколу — это ошибка настроек, а не сети: пока в поле
            // стоит адрес не того сервера, ответ будет тем же.
            err @ VlessError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            err @ VlessError::Oversized(_) => Self::InvalidConfig(err.to_string()),
            VlessError::UdpDisabled => Self::Unsupported("UDP"),
            VlessError::Disconnected(message) => Self::Disconnected(message),
            VlessError::Transport(err) => err.into(),
            VlessError::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = VlessError::Disconnected("сеть пропала".into()).into();
        assert!(err.is_retryable());
    }

    #[test]
    fn the_wrong_kind_of_server_is_not_retried() {
        let err: ProtocolError = VlessError::malformed("версия ответа 0x48").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_silent_server_is_retried() {
        let err: ProtocolError = VlessError::from(penguin_transport::TransportError::Timeout(
            "рукопожатие TLS",
        ))
        .into();
        assert!(err.is_retryable());
    }
}
