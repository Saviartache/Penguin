//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку. Отсюда правило — `407` от прокси обязан прийти как
//! [`HttpProxyError::AuthRejected`], а не как «не удалось подключиться»: иначе
//! клиент будет вечно долбиться в прокси с заведомо неверным паролем.

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type HttpProxyResult<T> = Result<T, HttpProxyError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum HttpProxyError {
    /// Настройки неверны или противоречивы.
    #[error("настройки прокси: {0}")]
    Config(String),

    /// Не удалось установить TLS с прокси.
    #[error("TLS до прокси: {0}")]
    Tls(String),

    /// Прокси отверг пароль: ответ `407` либо `403`.
    #[error("прокси отклонил пароль (код {status})")]
    AuthRejected {
        /// Код ответа HTTP.
        status: u16,
    },

    /// Прокси отказал в соединении с целевым адресом.
    #[error("прокси отказал в соединении с `{target}`: {status} {message}")]
    Refused {
        /// Куда пытались соединиться.
        target: String,
        /// Код ответа.
        status: u16,
        /// Строка причины, как её прислал прокси.
        message: String,
    },

    /// Ответ не разбирается как HTTP.
    ///
    /// Чаще всего это значит, что на указанном порту сидит не прокси, — или
    /// что к прокси под TLS постучались открытым текстом.
    #[error("прокси отвечает не по HTTP: {0}")]
    Malformed(String),

    /// Соединение с прокси оборвалось.
    #[error("соединение с прокси потеряно: {0}")]
    Disconnected(String),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl HttpProxyError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Прокси ответил не по протоколу.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }

    /// Ошибка TLS.
    pub fn tls(message: impl std::fmt::Display) -> Self {
        Self::Tls(message.to_string())
    }
}

// Перевод в общий язык, на котором говорит остальной клиент. Здесь и
// закрепляется обещание про повторные попытки.
impl From<HttpProxyError> for ProtocolError {
    fn from(err: HttpProxyError) -> Self {
        match err {
            HttpProxyError::Config(message) => Self::InvalidConfig(message),
            HttpProxyError::AuthRejected { .. } => Self::AuthRejected,
            // Не по HTTP — это ошибка настроек, а не сети: повторять
            // бессмысленно, пока в поле стоит адрес не того прокси.
            err @ HttpProxyError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            HttpProxyError::Tls(message) => Self::Connect(message),
            err @ HttpProxyError::Refused { .. } => Self::Unreachable(err.to_string()),
            HttpProxyError::Disconnected(message) => Self::Disconnected(message),
            HttpProxyError::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrong_password_is_not_retried() {
        let err: ProtocolError = HttpProxyError::AuthRejected { status: 407 }.into();
        assert!(
            !err.is_retryable(),
            "неверный пароль нельзя повторять бесконечно"
        );
    }

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = HttpProxyError::Disconnected("сеть пропала".into()).into();
        assert!(err.is_retryable());

        let err: ProtocolError = HttpProxyError::tls("рукопожатие не состоялось").into();
        assert!(err.is_retryable());
    }

    #[test]
    fn the_wrong_kind_of_proxy_is_not_retried() {
        let err: ProtocolError = HttpProxyError::malformed("ответ начинается с 0x05").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_refusal_names_the_target() {
        let err: ProtocolError = HttpProxyError::Refused {
            target: "example.com:443".to_owned(),
            status: 502,
            message: "Bad Gateway".to_owned(),
        }
        .into();
        assert!(err.to_string().contains("example.com:443"));
        assert!(err.is_retryable(), "чужой отказ — не наша поломка");
    }
}
