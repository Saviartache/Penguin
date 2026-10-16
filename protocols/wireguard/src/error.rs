//! Ошибки протокола; по варианту `supervisor` решает, повторять ли (`AGENTS.md` §4.2).
//!
//! `AuthRejected` не возвращается: WireGuard не присылает отказ, чужой ключ
//! неотличим от потерянной сети. Ключи сверяются до подключения
//! ([`crate::config::WireguardConfig::validate`]).
use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type WireguardResult<T> = Result<T, WireguardError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum WireguardError {
    /// Настройки неверны или противоречивы.
    #[error("настройки WireGuard: {0}")]
    Config(String),

    /// Пакет не по формату или не прошёл проверку подлинности (случаи неотличимы).
    #[error("пакет не по протоколу: {0}")]
    Malformed(String),

    /// Рукопожатие не уложилось в срок: сервер не ответил.
    #[error("рукопожатие WireGuard не уложилось в срок")]
    HandshakeTimeout,

    /// Сеанс истёк: ни разу не удалось обновить рукопожатие вовремя.
    #[error("сеанс WireGuard истёк: рукопожатие не обновилось за {0:?}")]
    SessionExpired(std::time::Duration),

    /// Направление закрыто, труба для пакетов не работает.
    #[error("направление WireGuard закрыто")]
    Closed,

    /// Сеть подвела: адрес не разрешился, сокет не открылся и т. п.
    #[error("сеть WireGuard: {0}")]
    Disconnected(String),

    /// Ошибка ввода-вывода на сокете.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl WireguardError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Пакет не по формату.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }

    /// Сеть подвела.
    pub fn disconnected(message: impl Into<String>) -> Self {
        Self::Disconnected(message.into())
    }
}

impl From<WireguardError> for ProtocolError {
    fn from(err: WireguardError) -> Self {
        match err {
            WireguardError::Config(message) => Self::InvalidConfig(message),
            err @ WireguardError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            err @ WireguardError::HandshakeTimeout => Self::Disconnected(err.to_string()),
            err @ WireguardError::SessionExpired(_) => Self::Disconnected(err.to_string()),
            err @ WireguardError::Closed => Self::Disconnected(err.to_string()),
            WireguardError::Disconnected(message) => Self::Disconnected(message),
            WireguardError::Io(err) => Self::Io(err),
        }
    }
}

impl From<penguin_transport::TransportError> for WireguardError {
    /// Нужен `deadline::within`; на практике встречается только `Timeout`.
    fn from(err: penguin_transport::TransportError) -> Self {
        use penguin_transport::TransportError as E;
        match err {
            E::Timeout(_) => Self::HandshakeTimeout,
            E::Config(message) => Self::Config(message),
            E::Address(message) | E::Malformed(message) => Self::Malformed(message),
            E::Rejected => Self::Malformed(err.to_string()),
            E::Disconnected(message) => Self::Disconnected(message),
            E::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_broken_config_is_not_retried() {
        let err: ProtocolError = WireguardError::config("пустой ключ").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_malformed_packet_is_not_retried() {
        let err: ProtocolError = WireguardError::malformed("метка не сошлась").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_handshake_timeout_is_retried() {
        let err: ProtocolError = WireguardError::HandshakeTimeout.into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_dead_session_is_retried() {
        let err: ProtocolError =
            WireguardError::SessionExpired(std::time::Duration::from_secs(180)).into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_closed_outbound_is_retried() {
        let err: ProtocolError = WireguardError::Closed.into();
        assert!(err.is_retryable());
    }

    #[test]
    fn an_io_error_is_retried() {
        let io = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        let err: ProtocolError = WireguardError::from(io).into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_resolve_failure_is_retried() {
        let err: ProtocolError = WireguardError::disconnected("example.com: не отвечает").into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_transport_timeout_becomes_a_handshake_timeout() {
        let err = WireguardError::from(penguin_transport::TransportError::Timeout(
            "рукопожатие WireGuard",
        ));
        assert!(matches!(err, WireguardError::HandshakeTimeout));
    }
}
