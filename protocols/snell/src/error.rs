//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку (`AGENTS.md` §4.2).
//!
//! Отдельного `AuthRejected` здесь нет, и это свойство протокола. Сервер
//! Snell не отвечает на неверный PSK отказом: он расшифровывает первый кусок
//! другим ключом, видит мусор и закрывает соединение. Со стороны клиента это
//! неотличимо от правки трафика по дороге — и общий слой AEAD называет обе
//! эти беды одним словом, [`TransportError::Rejected`], которое дальше и
//! становится `AuthRejected`.
//!
//! [`TransportError::Rejected`]: penguin_transport::TransportError::Rejected

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type SnellResult<T> = Result<T, SnellError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum SnellError {
    /// Настройки неверны или противоречивы.
    #[error("настройки Snell: {0}")]
    Config(String),

    /// Вывод ключа не удался.
    #[error("вывод ключа Snell: {0}")]
    Crypto(String),

    /// Сервер ответил отказом.
    ///
    /// Единственный случай, когда он вообще что-то объясняет: код и текст.
    #[error("сервер отказал (код {code}): {message}")]
    Refused {
        /// Код, который назвал сервер.
        code: u8,
        /// Текст, который он приложил.
        message: String,
    },

    /// Поток разъехался: читаем не то, что ждали.
    #[error("поток не по протоколу: {0}")]
    Malformed(String),

    /// Адрес не помещается в запись протокола.
    #[error("адрес не помещается в запрос: {0}")]
    Address(String),

    /// Датаграмма не помещается в кусок.
    #[error("датаграмма в {0} байт: в кусок столько не входит")]
    Oversized(usize),

    /// Проксирование UDP выключено или не умеет эта версия.
    #[error("{0}")]
    UdpUnsupported(String),

    /// Соединение оборвалось.
    #[error("соединение потеряно: {0}")]
    Disconnected(String),

    /// Ошибка общего транспорта: обфускация, кадр, срок рукопожатия.
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl SnellError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Вывод ключа не удался.
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto(message.into())
    }

    /// Поток разъехался.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }

    /// Адрес не помещается.
    pub fn address(message: impl Into<String>) -> Self {
        Self::Address(message.into())
    }

    /// Соединение оборвалось.
    pub fn disconnected(message: impl Into<String>) -> Self {
        Self::Disconnected(message.into())
    }
}

impl From<SnellError> for ProtocolError {
    fn from(err: SnellError) -> Self {
        match err {
            SnellError::Config(message) => Self::InvalidConfig(message),
            SnellError::Crypto(message) => Self::InvalidConfig(message),
            err @ SnellError::Address(_) => Self::InvalidConfig(err.to_string()),
            err @ SnellError::Oversized(_) => Self::InvalidConfig(err.to_string()),
            // Разъехавшийся поток — это не сеть: пока на том конце не тот
            // сервер или не та версия, повторять нечего.
            err @ SnellError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            // А отказ сервера — повод повторить: он бывает и временным,
            // например когда у адреса назначения не разрешается имя.
            err @ SnellError::Refused { .. } => Self::Disconnected(err.to_string()),
            SnellError::UdpUnsupported(_) => Self::Unsupported("UDP"),
            SnellError::Disconnected(message) => Self::Disconnected(message),
            SnellError::Transport(err) => err.into(),
            SnellError::Io(err) => Self::Io(err),
        }
    }
}

impl From<SnellError> for std::io::Error {
    /// Ошибка протокола внутри [`std::io`]: поток отдаёт наружу только его.
    fn from(err: SnellError) -> Self {
        match err {
            SnellError::Io(err) => err,
            other => Self::new(std::io::ErrorKind::InvalidData, other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrong_psk_arrives_as_a_refusal_from_the_shared_frame() {
        // Своего `AuthRejected` у Snell нет: неверный PSK виден только тем,
        // что метка не сошлась, и называет это общий слой.
        let err: ProtocolError =
            SnellError::from(penguin_transport::TransportError::Rejected).into();
        assert!(matches!(err, ProtocolError::AuthRejected));
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = SnellError::disconnected("сеть пропала").into();
        assert!(err.is_retryable());
    }

    #[test]
    fn the_wrong_version_is_not_retried() {
        // Версия — это настройка, и повторять с той же нечего.
        let err: ProtocolError = SnellError::malformed("ответ не по протоколу").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_refusal_from_the_server_is_retried() {
        // Сервер отказывает и временно: например, когда имя назначения не
        // разрешается у него.
        let err: ProtocolError = SnellError::Refused {
            code: 1,
            message: "connection refused".to_owned(),
        }
        .into();
        assert!(err.is_retryable());
    }

    #[test]
    fn udp_that_this_version_cannot_do_is_not_a_failure_to_retry() {
        let err: ProtocolError =
            SnellError::UdpUnsupported("версия ниже третьей".to_owned()).into();
        assert!(!err.is_retryable());
    }
}
