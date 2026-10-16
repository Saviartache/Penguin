//! Ошибки протокола.
//!
//! По варианту `supervisor` решает, повторять ли. `407` —
//! [`TrustTunnelError::AuthRejected`]: закрыть всю сессию (`PROTOCOL.md`, §9.2).

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type TrustTunnelResult<T> = Result<T, TrustTunnelError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum TrustTunnelError {
    /// Настройки неверны или противоречивы.
    #[error("настройки trusttunnel: {0}")]
    Config(String),

    /// Не удалось установить TLS с сервером.
    #[error("транспорт до сервера: {0}")]
    Transport(String),

    /// Сервер отверг `CONNECT`: код `407` (`PROTOCOL.md`, §5.2, §9.2).
    #[error("сервер отклонил пароль (код {status})")]
    AuthRejected {
        /// Код ответа.
        status: u16,
    },

    /// Сервер отказал в соединении с целевым адресом или пседво-хостом.
    #[error("сервер отказал в соединении с `{target}`: код {status}")]
    Refused {
        /// Куда пытались соединиться.
        target: String,
        /// Код ответа.
        status: u16,
    },

    /// Ответ или кадр не разбирается как ожидалось.
    #[error("сервер ответил не по протоколу: {0}")]
    Malformed(String),

    /// Соединение с сервером оборвалось.
    #[error("соединение с сервером потеряно: {0}")]
    Disconnected(String),

    /// Проверка живости (`CONNECT _check`, `PROTOCOL.md`, §8) не прошла: пересоздать сессию.
    #[error("проверка живости `_check` не прошла: {0}")]
    Unhealthy(String),

    /// Ошибка общего транспорта; классификацию повтора он уже сделал.
    #[error(transparent)]
    TransportCommon(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl TrustTunnelError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Ошибка транспорта: TLS-рукопожатие и подобное.
    pub fn transport(message: impl std::fmt::Display) -> Self {
        Self::Transport(message.to_string())
    }

    /// Ответ или кадр не разбирается.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }

    /// Обрыв соединения.
    pub fn disconnected(message: impl Into<String>) -> Self {
        Self::Disconnected(message.into())
    }
}

impl From<TrustTunnelError> for ProtocolError {
    fn from(err: TrustTunnelError) -> Self {
        match err {
            TrustTunnelError::Config(message) => Self::InvalidConfig(message),
            TrustTunnelError::AuthRejected { .. } => Self::AuthRejected,
            err @ TrustTunnelError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            TrustTunnelError::Transport(message) => Self::Connect(message),
            err @ TrustTunnelError::Refused { .. } => Self::Unreachable(err.to_string()),
            TrustTunnelError::Disconnected(message) => Self::Disconnected(message),
            TrustTunnelError::Unhealthy(message) => Self::Disconnected(message),
            TrustTunnelError::TransportCommon(err) => err.into(),
            TrustTunnelError::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrong_password_is_not_retried() {
        let err: ProtocolError = TrustTunnelError::AuthRejected { status: 407 }.into();
        assert!(
            !err.is_retryable(),
            "неверный пароль нельзя повторять бесконечно"
        );
    }

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = TrustTunnelError::disconnected("сеть пропала").into();
        assert!(err.is_retryable());

        let err: ProtocolError = TrustTunnelError::transport("рукопожатие не состоялось").into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_failed_health_check_is_retried_like_a_disconnect() {
        let err: ProtocolError = TrustTunnelError::Unhealthy("нет ответа".into()).into();
        assert!(err.is_retryable());
    }

    #[test]
    fn the_wrong_kind_of_server_is_not_retried() {
        let err: ProtocolError = TrustTunnelError::malformed("ответ не HTTP/2").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_refusal_names_the_target() {
        let err: ProtocolError = TrustTunnelError::Refused {
            target: "example.com:443".to_owned(),
            status: 502,
        }
        .into();
        assert!(err.to_string().contains("example.com:443"));
        assert!(err.is_retryable(), "чужой отказ — не наша поломка");
    }
}
