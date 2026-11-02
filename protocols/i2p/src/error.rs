//! Ошибки протокола.
//!
//! Отказ первого `CONNECT` — «сервер недоступен» (i2pd ещё строит туннели или
//! outproxy молчит), отказ второго — «цель недостижима».

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type I2pResult<T> = Result<T, I2pError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum I2pError {
    /// Настройки неверны.
    #[error("настройки I2P: {0}")]
    Config(String),

    /// На порту не HTTP-прокси.
    #[error("локальный прокси I2P отвечает не по HTTP: {0}")]
    Malformed(String),

    /// i2pd не дотянулся до outproxy: сеть I2P ещё не готова или outproxy выключен.
    #[error(
        "outproxy недоступен через I2P (код {0}); при первом запуске i2pd ищет узлы несколько минут"
    )]
    OutproxyUnreachable(u16),

    /// Outproxy отказал в соединении с целью.
    #[error("outproxy отказал в соединении с `{target}` (код {code})")]
    Refused {
        /// Куда пытались соединиться.
        target: String,
        /// Код ответа.
        code: u16,
    },

    /// Ошибка общего транспорта (классификацию повтора он уже сделал).
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl I2pError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }
}

impl From<I2pError> for ProtocolError {
    fn from(err: I2pError) -> Self {
        match err {
            I2pError::Config(message) => Self::InvalidConfig(message),
            err @ I2pError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            err @ I2pError::OutproxyUnreachable(_) => Self::Connect(err.to_string()),
            err @ I2pError::Refused { .. } => Self::Unreachable(err.to_string()),
            I2pError::Transport(err) => err.into(),
            I2pError::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unready_network_is_retried() {
        let err: ProtocolError = I2pError::OutproxyUnreachable(502).into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_wrong_port_is_not_retried() {
        let err: ProtocolError = I2pError::Malformed("SSH-2.0".into()).into();
        assert!(!err.is_retryable());
    }
}
