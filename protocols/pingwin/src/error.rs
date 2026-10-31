//! Ошибки протокола; по варианту `supervisor` решает, повторять ли (`AGENTS.md` §4.2).
//! [`PingwinError::Rejected`] ставится, когда в ответе нет верного доказательства
//! сервера (чужому он отвечает обычным сайтом).

use penguin_proto::error::ProtocolError;
use penguin_transport::h3::H3Error;
use thiserror::Error;

/// Результат операции протокола.
pub type PingwinResult<T> = Result<T, PingwinError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum PingwinError {
    /// Настройки неверны или противоречивы.
    #[error("настройки pingwin: {0}")]
    Config(String),

    /// Сервер не предъявил верного доказательства (пароль или ключ - не различить).
    #[error("сервер не узнал клиента: не тот пароль или не тот ключ сервера")]
    Rejected,

    /// Ответ сервера не разбирается как ожидалось.
    #[error("сервер ответил не по протоколу: {0}")]
    Malformed(String),

    /// Сервер не смог соединиться с целевым адресом.
    #[error("сервер не смог соединиться с `{target}`: {reason}")]
    Refused {
        /// Куда пытались соединиться.
        target: String,
        /// Что сказал сервер.
        reason: String,
    },

    /// Соединение с сервером оборвалось.
    #[error("соединение с сервером потеряно: {0}")]
    Disconnected(String),

    /// Датаграмма не помещается в датаграмму QUIC или капсулу.
    #[error("датаграмма длиной {0} байт не помещается в канал")]
    Oversized(usize),

    /// Ошибка общего транспорта (повторяемость уже определена им).
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl PingwinError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Ответ не разбирается.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }

    /// Обрыв соединения.
    pub fn disconnected(message: impl Into<String>) -> Self {
        Self::Disconnected(message.into())
    }
}

impl From<H3Error> for PingwinError {
    fn from(err: H3Error) -> Self {
        Self::Transport(err.into())
    }
}

impl From<h2::Error> for PingwinError {
    fn from(err: h2::Error) -> Self {
        Self::Disconnected(format!("HTTP/2: {err}"))
    }
}

impl From<PingwinError> for ProtocolError {
    fn from(err: PingwinError) -> Self {
        match err {
            PingwinError::Config(message) => Self::InvalidConfig(message),
            PingwinError::Rejected => Self::AuthRejected,
            err @ (PingwinError::Malformed(_) | PingwinError::Oversized(_)) => {
                Self::InvalidConfig(err.to_string())
            }
            err @ PingwinError::Refused { .. } => Self::Unreachable(err.to_string()),
            PingwinError::Disconnected(message) => Self::Disconnected(message),
            PingwinError::Transport(err) => err.into(),
            PingwinError::Io(err) => Self::Io(err),
        }
    }
}

impl From<PingwinError> for std::io::Error {
    /// Для `AsyncRead`: причина сохраняется текстом.
    fn from(err: PingwinError) -> Self {
        match err {
            PingwinError::Io(err) => err,
            other => Self::other(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unrecognised_client_is_not_retried() {
        let err: ProtocolError = PingwinError::Rejected.into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = PingwinError::disconnected("сеть пропала").into();
        assert!(err.is_retryable());
        let lost: ProtocolError = PingwinError::from(H3Error::closed("тайм-аут")).into();
        assert!(lost.is_retryable());
    }

    #[test]
    fn a_refusal_of_the_target_names_it_and_is_retried() {
        let err: ProtocolError = PingwinError::Refused {
            target: "example.com:443".to_owned(),
            reason: "нет маршрута".to_owned(),
        }
        .into();
        assert!(err.to_string().contains("example.com:443"));
        assert!(err.is_retryable(), "чужой отказ — не наша поломка");
    }

    #[test]
    fn the_wrong_kind_of_server_is_not_retried() {
        let err: ProtocolError = PingwinError::malformed("это не pingwin").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn the_reason_survives_the_trip_into_a_stream_error() {
        let err: std::io::Error = PingwinError::Refused {
            target: "example.com:443".to_owned(),
            reason: "нет маршрута".to_owned(),
        }
        .into();
        assert!(err.to_string().contains("нет маршрута"));
    }
}
