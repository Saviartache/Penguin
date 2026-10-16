//! Ошибки протокола.
//!
//! По варианту `supervisor` решает, повторять ли; неверный пароль приходит как
//! [`Socks5Error::AuthRejected`], не как обрыв.

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type Socks5Result<T> = Result<T, Socks5Error>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum Socks5Error {
    /// Настройки неверны или противоречивы.
    #[error("настройки SOCKS5: {0}")]
    Config(String),

    /// Прокси ответил не по протоколу (чаще всего на порту не SOCKS5).
    #[error("прокси отвечает не по SOCKS5: {0}")]
    Malformed(String),

    /// Прокси отверг учётные данные; повтор бессмысленен.
    #[error("прокси отклонил имя и пароль")]
    AuthRejected,

    /// Прокси не принял ни один способ проверки (обычно нужен пароль); повтор бессмысленен.
    #[error("прокси не принял ни один способ проверки подлинности — вероятно, нужен пароль")]
    AuthUnsupported,

    /// Прокси отказал в соединении с целевым адресом.
    #[error("прокси отказал в соединении с `{target}`: {reason}")]
    Refused {
        /// Куда пытались соединиться.
        target: String,
        /// Что ответил прокси.
        reason: &'static str,
    },

    /// Соединение с прокси оборвалось.
    #[error("соединение с прокси потеряно: {0}")]
    Disconnected(String),

    /// UDP выключен в настройках, а его попросили.
    #[error("проксирование UDP выключено в настройках профиля")]
    UdpDisabled,

    /// Ошибка общего транспорта (классификацию повтора он уже сделал).
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Socks5Error {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Прокси ответил не по протоколу.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }
}

impl From<Socks5Error> for ProtocolError {
    fn from(err: Socks5Error) -> Self {
        match err {
            Socks5Error::Config(message) => Self::InvalidConfig(message),
            Socks5Error::AuthRejected | Socks5Error::AuthUnsupported => Self::AuthRejected,
            err @ Socks5Error::Malformed(_) => Self::InvalidConfig(err.to_string()),
            Socks5Error::Refused { target, reason } => {
                Self::Unreachable(format!("{target}: {reason}"))
            }
            Socks5Error::Disconnected(message) => Self::Disconnected(message),
            Socks5Error::UdpDisabled => Self::Unsupported("UDP"),
            Socks5Error::Transport(err) => err.into(),
            Socks5Error::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrong_password_is_not_retried() {
        let err: ProtocolError = Socks5Error::AuthRejected.into();
        assert!(
            !err.is_retryable(),
            "неверный пароль нельзя повторять бесконечно"
        );

        let err: ProtocolError = Socks5Error::AuthUnsupported.into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_broken_connection_is_retried() {
        let err: ProtocolError = Socks5Error::Disconnected("сеть пропала".into()).into();
        assert!(err.is_retryable());
    }

    #[test]
    fn the_wrong_kind_of_proxy_is_not_retried() {
        let err: ProtocolError = Socks5Error::malformed("версия 71").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_refused_target_is_retried() {
        let err: ProtocolError = Socks5Error::Refused {
            target: "example.com:443".to_owned(),
            reason: "хост недостижим",
        }
        .into();
        assert!(err.is_retryable());
    }
}
