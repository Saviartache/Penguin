//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку. `407` на `CONNECT` — [`TrustTunnelError::AuthRejected`],
//! и его отличие от обрыва связи не в тексте, а в том, что предписывает
//! спецификация (`PROTOCOL.md`, §9.2): при нём клиент обязан закрыть **всю**
//! сессию и подключиться заново, а не просто повторить один поток — пароль,
//! отклонённый один раз, не станет верным при повторной попытке в том же
//! HTTP/2-соединении.

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
    ///
    /// У HTTP/2 нет строки причины, как у HTTP/1.1, — только код.
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

    /// Проверка живости (`CONNECT _check`, `PROTOCOL.md`, §8) не прошла.
    ///
    /// Отдельным вариантом от [`Self::Disconnected`]: неудачная проверка
    /// живости — это ещё не разрыв нижнего HTTP/2-соединения, а сигнал
    /// прекратить им пользоваться и поднять сессию заново.
    #[error("проверка живости `_check` не прошла: {0}")]
    Unhealthy(String),

    /// Ошибка общего транспорта: TLS, срок рукопожатия.
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

// Перевод в общий язык, на котором говорит остальной клиент. Здесь и
// закрепляется обещание про повторные попытки.
impl From<TrustTunnelError> for ProtocolError {
    fn from(err: TrustTunnelError) -> Self {
        match err {
            TrustTunnelError::Config(message) => Self::InvalidConfig(message),
            TrustTunnelError::AuthRejected { .. } => Self::AuthRejected,
            // Не по протоколу — это ошибка настроек (не тот сервер) или его
            // версии, а не сети: повторять бессмысленно, пока в поле стоит
            // не то.
            err @ TrustTunnelError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            TrustTunnelError::Transport(message) => Self::Connect(message),
            err @ TrustTunnelError::Refused { .. } => Self::Unreachable(err.to_string()),
            TrustTunnelError::Disconnected(message) => Self::Disconnected(message),
            // Неудачная проверка живости лечится ровно так же, как обрыв:
            // пересозданием направления.
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
        // Провал `_check` — не более, чем сигнал пересоздать сессию; сам по
        // себе он не говорит о неверном пароле.
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
