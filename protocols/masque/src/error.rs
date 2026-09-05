//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку. Неверные учётные данные — [`MasqueError::AuthRejected`],
//! и повторять их бессмысленно; обрыв связи — [`MasqueError::Disconnected`],
//! и его нужно повторять всегда.

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type MasqueResult<T> = Result<T, MasqueError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum MasqueError {
    /// Настройки неверны или противоречивы.
    #[error("настройки masque: {0}")]
    Config(String),

    /// Не удалось поднять TLS, QUIC или рукопожатие HTTP/3 с сервером.
    #[error("транспорт до сервера: {0}")]
    Transport(String),

    /// Сервер отверг учётные данные: код ответа `401`/`407`.
    #[error("сервер отклонил учётные данные (код {status})")]
    AuthRejected {
        /// Код ответа.
        status: u16,
    },

    /// Сервер отказал в проксировании: любой код вне `2xx`, кроме `401`/`407`.
    #[error("сервер отказал в CONNECT-UDP до `{target}`: код {status}")]
    Refused {
        /// Куда пытались открыть канал.
        target: String,
        /// Код ответа.
        status: u16,
    },

    /// Ответ не разбирается как ожидалось: нет `capsule-protocol: ?1`,
    /// обрезанная капсула, полезная нагрузка сверх предела.
    #[error("сервер ответил не по протоколу MASQUE: {0}")]
    Malformed(String),

    /// Канал с сервером оборвался во время работы.
    #[error("канал с сервером потерян: {0}")]
    Disconnected(String),

    /// Ошибка общего транспорта: TLS, срок рукопожатия.
    #[error(transparent)]
    TransportCommon(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl MasqueError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Ошибка транспорта: TLS-рукопожатие, поднятие QUIC, рукопожатие HTTP/3.
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
impl From<MasqueError> for ProtocolError {
    fn from(err: MasqueError) -> Self {
        match err {
            MasqueError::Config(message) => Self::InvalidConfig(message),
            MasqueError::AuthRejected { .. } => Self::AuthRejected,
            // Не по протоколу — это признак не того сервера или не той
            // версии, а не сети: повторять бессмысленно, пока в поле стоит
            // не тот адрес.
            err @ MasqueError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            MasqueError::Transport(message) => Self::Connect(message),
            err @ MasqueError::Refused { .. } => Self::Unreachable(err.to_string()),
            MasqueError::Disconnected(message) => Self::Disconnected(message),
            MasqueError::TransportCommon(err) => err.into(),
            MasqueError::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_credentials_are_not_retried() {
        let err: ProtocolError = MasqueError::AuthRejected { status: 407 }.into();
        assert!(
            !err.is_retryable(),
            "неверные учётные данные нельзя повторять бесконечно"
        );
    }

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = MasqueError::Disconnected("сеть пропала".into()).into();
        assert!(err.is_retryable());

        let err: ProtocolError = MasqueError::transport("рукопожатие QUIC не завершилось").into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_malformed_response_is_not_retried() {
        let err: ProtocolError = MasqueError::malformed("нет capsule-protocol").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_refusal_names_the_target() {
        let err: ProtocolError = MasqueError::Refused {
            target: "203.0.113.5:53".to_owned(),
            status: 502,
        }
        .into();
        assert!(err.to_string().contains("203.0.113.5:53"));
        assert!(err.is_retryable(), "чужой отказ — не наша поломка");
    }
}
