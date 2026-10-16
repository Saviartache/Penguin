//! Ошибки протокола.
//!
//! По варианту `supervisor` решает, повторять ли (AGENTS §4.2). `AuthRejected` нет
//! по замыслу протокола: неверный пароль клиенту не виден.

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type TrojanResult<T> = Result<T, TrojanError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum TrojanError {
    /// Настройки неверны или противоречивы.
    #[error("настройки Trojan: {0}")]
    Config(String),

    /// Поток разъехался: читаем не то, что ждали.
    #[error("поток не по протоколу: {0}")]
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

    /// Ошибка общего транспорта: TLS, gRPC, XHTTP, срок рукопожатия, адрес.
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl TrojanError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Поток разъехался.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }
}

impl From<TrojanError> for ProtocolError {
    fn from(err: TrojanError) -> Self {
        match err {
            TrojanError::Config(message) => Self::InvalidConfig(message),
            err @ TrojanError::Oversized(_) => Self::InvalidConfig(err.to_string()),
            err @ TrojanError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            TrojanError::UdpDisabled => Self::Unsupported("UDP"),
            TrojanError::Disconnected(message) => Self::Disconnected(message),
            TrojanError::Transport(err) => err.into(),
            TrojanError::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = TrojanError::Disconnected("сеть пропала".into()).into();
        assert!(err.is_retryable());
    }

    #[test]
    fn the_wrong_kind_of_server_is_not_retried() {
        let err: ProtocolError = TrojanError::malformed("нет CRLF").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_silent_server_is_retried() {
        let err: ProtocolError = TrojanError::from(penguin_transport::TransportError::Timeout(
            "рукопожатие TLS",
        ))
        .into();
        assert!(err.is_retryable());
    }

    #[test]
    fn udp_turned_off_is_not_a_failure_to_retry() {
        let err: ProtocolError = TrojanError::UdpDisabled.into();
        assert!(!err.is_retryable());
    }
}
