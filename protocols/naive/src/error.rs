//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку. Неверный пароль — [`NaiveError::AuthRejected`], и
//! его повторять нельзя; обрыв связи — [`NaiveError::Disconnected`], и его
//! нужно повторять всегда.

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type NaiveResult<T> = Result<T, NaiveError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum NaiveError {
    /// Настройки неверны или противоречивы.
    #[error("настройки naive: {0}")]
    Config(String),

    /// Не удалось установить TLS или QUIC с сервером.
    #[error("транспорт до сервера: {0}")]
    Transport(String),

    /// Сервер отверг `CONNECT`: коды `401`/`407`.
    ///
    /// В HTTP/2 и HTTP/3 у ответа нет строки причины — только код, поэтому
    /// текста здесь меньше, чем у `http-proxy`.
    #[error("сервер отклонил пароль (код {status})")]
    AuthRejected {
        /// Код ответа.
        status: u16,
    },

    /// Сервер отказал в соединении с целевым адресом.
    #[error("сервер отказал в соединении с `{target}`: код {status}")]
    Refused {
        /// Куда пытались соединиться.
        target: String,
        /// Код ответа.
        status: u16,
    },

    /// Ответ не разбирается как ожидалось.
    #[error("сервер ответил не по протоколу: {0}")]
    Malformed(String),

    /// Соединение с сервером оборвалось.
    #[error("соединение с сервером потеряно: {0}")]
    Disconnected(String),

    /// Ошибка общего транспорта: TLS, срок рукопожатия, запись адреса.
    ///
    /// Отдельным вариантом, а не разобранной на части: классификацию
    /// «повторять / не повторять» транспорт уже сделал, и повторять её здесь
    /// значит однажды разойтись с ней.
    #[error(transparent)]
    TransportCommon(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl NaiveError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Ошибка транспорта: TLS-рукопожатие, поднятие QUIC-эндпойнта и т. п.
    pub fn transport(message: impl std::fmt::Display) -> Self {
        Self::Transport(message.to_string())
    }

    /// Ответ не разбирается.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }
}

// Перевод в общий язык, на котором говорит остальной клиент. Здесь и
// закрепляется обещание про повторные попытки.
impl From<NaiveError> for ProtocolError {
    fn from(err: NaiveError) -> Self {
        match err {
            NaiveError::Config(message) => Self::InvalidConfig(message),
            NaiveError::AuthRejected { .. } => Self::AuthRejected,
            // Не по протоколу — это ошибка настроек (не тот адрес, не тот
            // сервер), а не сети: повторять бессмысленно, пока в поле стоит
            // не то.
            err @ NaiveError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            NaiveError::Transport(message) => Self::Connect(message),
            err @ NaiveError::Refused { .. } => Self::Unreachable(err.to_string()),
            NaiveError::Disconnected(message) => Self::Disconnected(message),
            NaiveError::TransportCommon(err) => err.into(),
            NaiveError::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrong_password_is_not_retried() {
        let err: ProtocolError = NaiveError::AuthRejected { status: 407 }.into();
        assert!(
            !err.is_retryable(),
            "неверный пароль нельзя повторять бесконечно"
        );
    }

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = NaiveError::Disconnected("сеть пропала".into()).into();
        assert!(err.is_retryable());

        let err: ProtocolError = NaiveError::transport("рукопожатие не состоялось").into();
        assert!(err.is_retryable());
    }

    #[test]
    fn the_wrong_kind_of_server_is_not_retried() {
        let err: ProtocolError = NaiveError::malformed("ответ не HTTP/2").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_refusal_names_the_target() {
        let err: ProtocolError = NaiveError::Refused {
            target: "example.com:443".to_owned(),
            status: 502,
        }
        .into();
        assert!(err.to_string().contains("example.com:443"));
        assert!(err.is_retryable(), "чужой отказ — не наша поломка");
    }
}
