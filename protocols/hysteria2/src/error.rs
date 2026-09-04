//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку. Отсюда правило — неверный пароль обязан прийти как
//! [`Hysteria2Error::AuthRejected`], а не как «не удалось подключиться»: иначе
//! клиент будет вечно долбиться в сервер с заведомо неверным паролем.

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type Hysteria2Result<T> = Result<T, Hysteria2Error>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum Hysteria2Error {
    /// Настройки неверны или противоречивы.
    #[error("настройки Hysteria 2: {0}")]
    Config(String),

    /// Не удалось разрешить имя сервера.
    #[error("не удалось разрешить имя сервера `{0}`")]
    Resolve(String),

    /// Не удалось установить соединение QUIC.
    #[error("QUIC: {0}")]
    Quic(String),

    /// Сервер отклонил пароль.
    ///
    /// Ответ, отличный от 233. Отдельный вариант, потому что повторять
    /// бессмысленно.
    #[error("сервер отклонил аутентификацию (код {status})")]
    AuthRejected {
        /// Код ответа HTTP/3.
        status: u16,
    },

    /// Аутентификация не дошла до ответа: разрыв на середине обмена.
    #[error("аутентификация не завершилась: {0}")]
    Auth(String),

    /// Сервер отказал в соединении с целевым адресом.
    #[error("сервер отказал в соединении с `{target}`: {message}")]
    Refused {
        /// Куда пытались соединиться.
        target: String,
        /// Что ответил сервер.
        message: String,
    },

    /// Соединение с сервером потеряно.
    #[error("соединение с сервером потеряно: {0}")]
    Disconnected(String),

    /// Сервер не поддерживает UDP, а его попросили.
    #[error("сервер не поддерживает проксирование UDP")]
    UdpDisabled,

    /// Датаграмма не отправляется: не помещается даже разрезанная.
    #[error("датаграмма длиной {size} байт не помещается в путевой MTU")]
    DatagramTooLarge {
        /// Длина датаграммы.
        size: usize,
    },

    /// Ошибка общего транспорта: TLS, срок рукопожатия, запись адреса.
    ///
    /// Отдельным вариантом, а не разобранной на части: классификацию
    /// «повторять / не повторять» транспорт уже сделал, и повторять её здесь
    /// значит однажды разойтись с ней.
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Hysteria2Error {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Ошибка QUIC.
    pub fn quic(message: impl std::fmt::Display) -> Self {
        Self::Quic(message.to_string())
    }
}

// Перевод в общий язык, на котором говорит остальной клиент. Здесь и
// закрепляется обещание про повторные попытки: `AuthRejected` и `Config`
// попадают в невосстановимые варианты, всё остальное — в восстановимые.
impl From<Hysteria2Error> for ProtocolError {
    fn from(err: Hysteria2Error) -> Self {
        match err {
            Hysteria2Error::Config(message) => Self::InvalidConfig(message),
            Hysteria2Error::AuthRejected { .. } => Self::AuthRejected,
            Hysteria2Error::Auth(message) => Self::Connect(message),
            Hysteria2Error::Resolve(host) => {
                Self::Connect(format!("не удалось разрешить имя `{host}`"))
            }
            Hysteria2Error::Quic(message) => Self::Connect(message),
            Hysteria2Error::Refused { target, message } => {
                Self::Unreachable(format!("{target}: {message}"))
            }
            Hysteria2Error::Disconnected(message) => Self::Disconnected(message),
            Hysteria2Error::UdpDisabled => Self::Unsupported("UDP"),
            err @ Hysteria2Error::DatagramTooLarge { .. } => Self::Unreachable(err.to_string()),
            Hysteria2Error::Transport(err) => err.into(),
            Hysteria2Error::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failure_is_not_retried() {
        let err: ProtocolError = Hysteria2Error::AuthRejected { status: 404 }.into();
        assert!(
            !err.is_retryable(),
            "неверный пароль нельзя повторять бесконечно"
        );
    }

    #[test]
    fn network_failure_is_retried() {
        let err: ProtocolError = Hysteria2Error::Disconnected("сеть пропала".into()).into();
        assert!(err.is_retryable());

        let err: ProtocolError = Hysteria2Error::quic("handshake timeout").into();
        assert!(err.is_retryable());
    }

    #[test]
    fn config_failure_is_not_retried() {
        let err: ProtocolError = Hysteria2Error::config("не задан пароль").into();
        assert!(!err.is_retryable());
    }
}
