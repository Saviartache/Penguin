//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку (`AGENTS.md` §4.2).
//!
//! Одного варианта здесь нет и быть не может — `AuthRejected`. Сервер AnyTLS
//! на опознание не отвечает ничем: узнал отпечаток — открывает сессию, не
//! узнал — закрывает соединение или отдаёт наши байты сайту, за который себя
//! выдаёт. Со стороны клиента это выглядит оборванным соединением, и отличить
//! его от оборванного соединения нельзя (см. документ крейта).

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type AnyTlsResult<T> = Result<T, AnyTlsError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum AnyTlsError {
    /// Настройки неверны или противоречивы.
    #[error("настройки AnyTLS: {0}")]
    Config(String),

    /// Поток разъехался: читаем не то, что ждали.
    #[error("сессия не по протоколу: {0}")]
    Malformed(String),

    /// Кусок не помещается в длину, которая пишется двумя байтами.
    #[error("кусок в {0} байт: длина кадра пишется двумя байтами")]
    Oversized(usize),

    /// Сервер прислал `cmdAlert` и закрыл сессию.
    #[error("сервер отказал: {0}")]
    Alert(String),

    /// Проксирование UDP выключено в настройках профиля.
    #[error("проксирование UDP выключено в настройках профиля")]
    UdpDisabled,

    /// Сессия закрылась.
    #[error("сессия потеряна: {0}")]
    Disconnected(String),

    /// Ошибка общего транспорта: TLS, срок рукопожатия, адрес.
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl AnyTlsError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Сессия разъехалась.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }

    /// Сессия закрылась.
    pub fn disconnected(message: impl Into<String>) -> Self {
        Self::Disconnected(message.into())
    }
}

impl From<AnyTlsError> for ProtocolError {
    fn from(err: AnyTlsError) -> Self {
        match err {
            AnyTlsError::Config(message) => Self::InvalidConfig(message),
            err @ AnyTlsError::Oversized(_) => Self::InvalidConfig(err.to_string()),
            // Разъехавшаяся сессия — это не сеть: пока на том конце не тот
            // сервер, повторять нечего.
            err @ AnyTlsError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            // А это как раз повторять стоит: сервер мог отказать на время —
            // например, исчерпан предел соединений.
            err @ AnyTlsError::Alert(_) => Self::Disconnected(err.to_string()),
            AnyTlsError::UdpDisabled => Self::Unsupported("UDP"),
            AnyTlsError::Disconnected(message) => Self::Disconnected(message),
            AnyTlsError::Transport(err) => err.into(),
            AnyTlsError::Io(err) => Self::Io(err),
        }
    }
}

impl From<AnyTlsError> for std::io::Error {
    /// Ошибка протокола внутри [`std::io`]: поток отдаёт наружу только его.
    fn from(err: AnyTlsError) -> Self {
        match err {
            AnyTlsError::Io(err) => err,
            other => Self::other(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = AnyTlsError::disconnected("сеть пропала").into();
        assert!(err.is_retryable());
    }

    #[test]
    fn the_wrong_kind_of_server_is_not_retried() {
        // Пока в поле стоит адрес не того сервера, ответ будет тем же.
        let err: ProtocolError = AnyTlsError::malformed("неизвестная команда").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_silent_server_is_retried() {
        // Срок приходит из общего транспорта и обязан сохранить смысл.
        let err: ProtocolError = AnyTlsError::from(penguin_transport::TransportError::Timeout(
            "рукопожатие TLS",
        ))
        .into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_refusal_from_the_server_is_retried() {
        // `cmdAlert` — это «сейчас нельзя», а не «настройки неверны»: сервер
        // шлёт его и когда кончились места, и когда клиент устарел.
        let err: ProtocolError = AnyTlsError::Alert("too many sessions".into()).into();
        assert!(err.is_retryable());
    }

    #[test]
    fn udp_turned_off_is_not_a_failure_to_retry() {
        let err: ProtocolError = AnyTlsError::UdpDisabled.into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn an_io_error_stays_itself_on_the_way_out() {
        // Поток отдаёт наружу `io::Error`, и `WouldBlock` не должен по дороге
        // превратиться в `Other`: на него смотрят те, кто копирует байты.
        let err = std::io::Error::new(std::io::ErrorKind::WouldBlock, "занято");
        let back: std::io::Error = AnyTlsError::Io(err).into();
        assert_eq!(back.kind(), std::io::ErrorKind::WouldBlock);
    }
}
