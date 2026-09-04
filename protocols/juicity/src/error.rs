//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку (`AGENTS.md` §4.2).
//!
//! `AuthRejected` здесь есть — и это отличает Juicity от Trojan и AnyTLS.
//! Сервер, не сошедшийся отпечатком, закрывает соединение QUIC с кодом
//! [`AUTH_FAILED`](crate::link::AUTH_FAILED), а не молча отдаёт трафик
//! чужому сайту. Повторять с тем же паролем нечего, и клиент об этом знает.

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type JuicityResult<T> = Result<T, JuicityError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum JuicityError {
    /// Настройки неверны или противоречивы.
    #[error("настройки Juicity: {0}")]
    Config(String),

    /// Сервер не признал UUID и пароль.
    #[error("сервер отклонил опознание: не тот UUID или пароль")]
    AuthRejected,

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

    /// Ошибка общего транспорта: TLS, срок рукопожатия, адрес.
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl JuicityError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Поток разъехался.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }

    /// Соединение оборвалось.
    pub fn disconnected(message: impl Into<String>) -> Self {
        Self::Disconnected(message.into())
    }
}

impl From<JuicityError> for ProtocolError {
    fn from(err: JuicityError) -> Self {
        match err {
            JuicityError::Config(message) => Self::InvalidConfig(message),
            JuicityError::AuthRejected => Self::AuthRejected,
            err @ JuicityError::Oversized(_) => Self::InvalidConfig(err.to_string()),
            // Разъехавшийся поток — это не сеть: пока на том конце не тот
            // сервер, повторять нечего.
            err @ JuicityError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            JuicityError::UdpDisabled => Self::Unsupported("UDP"),
            JuicityError::Disconnected(message) => Self::Disconnected(message),
            JuicityError::Transport(err) => err.into(),
            JuicityError::Io(err) => Self::Io(err),
        }
    }
}

impl From<JuicityError> for std::io::Error {
    /// Ошибка протокола внутри [`std::io`]: поток отдаёт наружу только его.
    fn from(err: JuicityError) -> Self {
        match err {
            JuicityError::Io(err) => err,
            other => Self::other(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrong_password_is_not_retried() {
        // Ради этого варианта и стоило читать код сервера: он закрывает
        // соединение с отдельным кодом, а не молчит, как Trojan.
        let err: ProtocolError = JuicityError::AuthRejected.into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = JuicityError::disconnected("сеть пропала").into();
        assert!(err.is_retryable());
    }

    #[test]
    fn the_wrong_kind_of_server_is_not_retried() {
        let err: ProtocolError = JuicityError::malformed("неизвестный тип адреса").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_silent_server_is_retried() {
        let err: ProtocolError = JuicityError::from(penguin_transport::TransportError::Timeout(
            "рукопожатие QUIC",
        ))
        .into();
        assert!(err.is_retryable());
    }

    #[test]
    fn udp_turned_off_is_not_a_failure_to_retry() {
        let err: ProtocolError = JuicityError::UdpDisabled.into();
        assert!(!err.is_retryable());
    }
}
