//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку (`AGENTS.md` §4.2).
//!
//! GOST Relay — первый из уже написанных протоколов, где неверные имя и
//! пароль сообщаются отдельным кодом состояния (`StatusUnauthorized`,
//! `go-gost/x`, `handler/relay/handler.go`, функция `Handle`), а не
//! молчанием и не разрывом соединения. Поэтому `AuthRejected` здесь —
//! прямой перевод этого кода, а не единственно возможное предположение.

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type GostRelayResult<T> = Result<T, GostRelayError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum GostRelayError {
    /// Настройки неверны или противоречивы.
    #[error("настройки GOST Relay: {0}")]
    Config(String),

    /// Сервер ответил не по протоколу.
    #[error("ответ не по протоколу: {0}")]
    Malformed(String),

    /// Сервер отверг имя и пароль (`StatusUnauthorized`).
    #[error("сервер отклонил имя и пароль")]
    AuthRejected,

    /// Сервер отказал в запросе с объявленной причиной.
    ///
    /// Сюда попадают все статусы, кроме успеха и `StatusUnauthorized`:
    /// `BadRequest`, `Forbidden`, `Timeout`, `ServiceUnavailable`,
    /// `HostUnreachable`, `NetworkUnreachable`, `InternalServerError` и
    /// любой код, которого нет в `relay.go`. Различать их дальше клиенту
    /// незачем: во всех случаях этот адрес сейчас не открылся, а другой
    /// или тот же чуть позже — вполне может.
    #[error("сервер отказал в `{target}`: {reason}")]
    Refused {
        /// Куда пытались подключиться.
        target: String,
        /// Что ответил сервер.
        reason: &'static str,
    },

    /// Датаграмма не помещается в объявляемую длину.
    #[error("датаграмма в {0} байт: длина пишется двумя байтами")]
    Oversized(usize),

    /// Проксирование UDP выключено в настройках профиля.
    #[error("проксирование UDP выключено в настройках профиля")]
    UdpDisabled,

    /// Соединение оборвалось.
    #[error("соединение потеряно: {0}")]
    Disconnected(String),

    /// Ошибка общего транспорта: TLS, WebSocket, срок рукопожатия, адрес.
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl GostRelayError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Сервер ответил не по протоколу.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }

    /// Соединение оборвалось.
    pub fn disconnected(message: impl Into<String>) -> Self {
        Self::Disconnected(message.into())
    }
}

impl From<GostRelayError> for ProtocolError {
    fn from(err: GostRelayError) -> Self {
        match err {
            GostRelayError::Config(message) => Self::InvalidConfig(message),
            // Не по протоколу — это ошибка настроек, а не сети: пока в поле
            // стоит адрес не того сервера, ответ будет тем же.
            err @ GostRelayError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            GostRelayError::AuthRejected => Self::AuthRejected,
            // Отказ в одном адресе не означает, что сервер сломан целиком.
            GostRelayError::Refused { target, reason } => {
                Self::Unreachable(format!("{target}: {reason}"))
            }
            err @ GostRelayError::Oversized(_) => Self::InvalidConfig(err.to_string()),
            GostRelayError::UdpDisabled => Self::Unsupported("UDP"),
            GostRelayError::Disconnected(message) => Self::Disconnected(message),
            GostRelayError::Transport(err) => err.into(),
            GostRelayError::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrong_password_is_not_retried() {
        let err: ProtocolError = GostRelayError::AuthRejected.into();
        assert!(!err.is_retryable());
        assert!(matches!(err, ProtocolError::AuthRejected));
    }

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = GostRelayError::disconnected("сеть пропала").into();
        assert!(err.is_retryable());
    }

    #[test]
    fn the_wrong_kind_of_server_is_not_retried() {
        let err: ProtocolError = GostRelayError::malformed("версия ответа 0x48").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_refused_target_is_retried() {
        // Отказ в одном адресе (например, `HostUnreachable`) не означает,
        // что сервер сломан: другой адрес через него вполне может открыться.
        let err: ProtocolError = GostRelayError::Refused {
            target: "example.com:443".to_owned(),
            reason: "узел недостижим",
        }
        .into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_silent_server_is_retried() {
        let err: ProtocolError = GostRelayError::from(penguin_transport::TransportError::Timeout(
            "заголовок GOST Relay",
        ))
        .into();
        assert!(err.is_retryable());
    }

    #[test]
    fn udp_turned_off_is_not_a_failure_to_retry() {
        let err: ProtocolError = GostRelayError::UdpDisabled.into();
        assert!(!err.is_retryable());
    }
}
