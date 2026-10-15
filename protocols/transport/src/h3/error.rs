//! Ошибки HTTP/3.

use std::io;

use thiserror::Error;

use super::code::QPACK_DECOMPRESSION_FAILED;
use super::qpack::QpackError;
use crate::error::TransportError;

/// Результат операции HTTP/3.
pub type H3Result<T> = Result<T, H3Error>;

/// Что пошло не так в HTTP/3.
#[derive(Debug, Clone, Error)]
pub enum H3Error {
    /// Собеседник нарушил HTTP/3; соединение закрыто с кодом `code`.
    #[error("собеседник нарушил HTTP/3 (код {code:#x}): {reason}")]
    Protocol {
        /// Код ошибки соединения (RFC 9114, §8.1).
        code: u64,
        /// Что именно нарушено.
        reason: String,
    },

    /// Ответ построен неверно. Ошибка потока, соединение живо.
    #[error("ответ HTTP/3 построен неверно: {0}")]
    Message(String),

    /// Собеседник сбросил поток.
    #[error("поток HTTP/3 сброшен собеседником (код {0:#x})")]
    Reset(u64),

    /// Сервер не объявил то, без чего запрос нельзя слать.
    #[error("сервер HTTP/3 не поддерживает {0}")]
    Unsupported(&'static str),

    /// Датаграмма длиннее, чем сейчас пропускает путь QUIC.
    #[error("датаграмма длиннее, чем пропускает путь QUIC")]
    DatagramTooLarge,

    /// Соединение или поток закрыты.
    #[error("соединение HTTP/3 потеряно: {0}")]
    Closed(String),
}

impl H3Error {
    /// Нарушение протокола с кодом ошибки соединения.
    pub fn protocol(code: u64, reason: impl Into<String>) -> Self {
        Self::Protocol {
            code,
            reason: reason.into(),
        }
    }

    /// Обрыв соединения или потока.
    pub fn closed(err: impl std::fmt::Display) -> Self {
        Self::Closed(err.to_string())
    }
}

impl From<QpackError> for H3Error {
    fn from(err: QpackError) -> Self {
        Self::protocol(QPACK_DECOMPRESSION_FAILED, err.to_string())
    }
}

impl From<H3Error> for TransportError {
    fn from(err: H3Error) -> Self {
        match err {
            // Чужой разговор вместо HTTP/3 сам не исправится — повторять нечего.
            err @ (H3Error::Protocol { .. }
            | H3Error::Message(_)
            | H3Error::Unsupported(_)
            | H3Error::DatagramTooLarge) => Self::Malformed(err.to_string()),
            err @ (H3Error::Reset(_) | H3Error::Closed(_)) => Self::Disconnected(err.to_string()),
        }
    }
}

impl From<H3Error> for io::Error {
    fn from(err: H3Error) -> Self {
        let kind = match err {
            H3Error::Reset(_) => io::ErrorKind::ConnectionReset,
            H3Error::Closed(_) => io::ErrorKind::ConnectionAborted,
            _ => io::ErrorKind::InvalidData,
        };
        io::Error::new(kind, err)
    }
}

#[cfg(test)]
mod tests {
    use penguin_proto::error::ProtocolError;

    use super::*;

    #[test]
    fn a_lost_connection_is_retried_and_a_broken_peer_is_not() {
        let lost: ProtocolError = TransportError::from(H3Error::closed("тайм-аут")).into();
        assert!(lost.is_retryable());

        let broken: ProtocolError =
            TransportError::from(H3Error::protocol(0x0105, "кадр не на месте")).into();
        assert!(!broken.is_retryable());
    }
}
