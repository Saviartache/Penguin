//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку (`AGENTS.md` §4.2). Здесь оно проходит по одной
//! границе — отвергнутое опознание против всего остального.
//!
//! Отвергнутое опознание у Pingwin выглядит не как отказ, а как молчание:
//! сервер, не узнавший клиента, отдаёт соединение прикрытию и ведёт себя как
//! обычный сайт (см. [`crate::handshake`]). Поэтому [`PingwinError::Rejected`]
//! ставится не по ответу сервера, а по тому, что ответ **не расшифровался**, —
//! и повторять его бессмысленно ровно так же, как неверный пароль.

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type PingwinResult<T> = Result<T, PingwinError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum PingwinError {
    /// Настройки неверны или противоречивы.
    #[error("настройки pingwin: {0}")]
    Config(String),

    /// Ответ сервера не расшифровался.
    ///
    /// Означает одно из двух: пароль не тот либо постоянный ключ сервера не
    /// тот. Различить их нельзя — и не нужно: лечатся они одинаково, правкой
    /// профиля, а не повторной попыткой.
    #[error("сервер не узнал клиента: не тот пароль или не тот ключ сервера")]
    Rejected,

    /// Ответ сервера не разбирается как ожидалось.
    #[error("сервер ответил не по протоколу: {0}")]
    Malformed(String),

    /// Сервер отказал в соединении с целевым адресом.
    #[error("сервер не смог соединиться с `{target}`: {reason}")]
    Refused {
        /// Куда пытались соединиться.
        target: String,
        /// Что сказал сервер.
        reason: String,
    },

    /// Соединение с сервером оборвалось.
    #[error("соединение с сервером потеряно: {0}")]
    Disconnected(String),

    /// Кадр не помещается в запись.
    #[error("кадр длиной {0} байт не помещается в запись")]
    Oversized(usize),

    /// Ошибка общего транспорта: обход DPI, срок рукопожатия, запись адреса.
    ///
    /// Отдельным вариантом, а не разобранной на части: классификацию
    /// «повторять / не повторять» транспорт уже сделал, и повторять её здесь
    /// значит однажды разойтись с ней.
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка сборки `ClientHello`.
    #[error(transparent)]
    Utls(#[from] penguin_utls::UtlsError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl PingwinError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Ответ не разбирается.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }

    /// Обрыв соединения.
    pub fn disconnected(message: impl Into<String>) -> Self {
        Self::Disconnected(message.into())
    }
}

// Перевод в общий язык, на котором говорит остальной клиент.
impl From<PingwinError> for ProtocolError {
    fn from(err: PingwinError) -> Self {
        match err {
            PingwinError::Config(message) => Self::InvalidConfig(message),
            PingwinError::Rejected => Self::AuthRejected,
            // Не по протоколу — это ошибка настроек (не тот сервер) или его
            // версии, а не сети: повторять бессмысленно, пока в поле стоит
            // не то.
            err @ PingwinError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            err @ PingwinError::Refused { .. } => Self::Unreachable(err.to_string()),
            PingwinError::Disconnected(message) => Self::Disconnected(message),
            err @ PingwinError::Oversized(_) => Self::InvalidConfig(err.to_string()),
            PingwinError::Transport(err) => err.into(),
            err @ PingwinError::Utls(_) => Self::InvalidConfig(err.to_string()),
            PingwinError::Io(err) => Self::Io(err),
        }
    }
}

impl From<PingwinError> for std::io::Error {
    /// Ошибка внутри уже открытого потока.
    ///
    /// Нужен ради [`AsyncRead`](tokio::io::AsyncRead) и
    /// [`AsyncWrite`](tokio::io::AsyncWrite): у них язык один — `io::Error`, —
    /// и текст причины иначе потерялся бы по дороге к приложению.
    fn from(err: PingwinError) -> Self {
        match err {
            PingwinError::Io(err) => err,
            other => Self::other(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unrecognised_client_is_not_retried() {
        // Повторять здесь нечего: и не тот пароль, и не тот ключ сервера
        // лечатся правкой профиля.
        let err: ProtocolError = PingwinError::Rejected.into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = PingwinError::disconnected("сеть пропала").into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_refusal_of_the_target_names_it_and_is_retried() {
        let err: ProtocolError = PingwinError::Refused {
            target: "example.com:443".to_owned(),
            reason: "нет маршрута".to_owned(),
        }
        .into();
        assert!(err.to_string().contains("example.com:443"));
        assert!(err.is_retryable(), "чужой отказ — не наша поломка");
    }

    #[test]
    fn the_wrong_kind_of_server_is_not_retried() {
        let err: ProtocolError = PingwinError::malformed("это не приветствие").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn the_reason_survives_the_trip_into_a_stream_error() {
        // Приложение видит поток, а не протокол: если причина не доедет,
        // в журнале останется «соединение закрыто» без единой подробности.
        let err: std::io::Error = PingwinError::Refused {
            target: "example.com:443".to_owned(),
            reason: "нет маршрута".to_owned(),
        }
        .into();
        assert!(err.to_string().contains("нет маршрута"));
    }
}
