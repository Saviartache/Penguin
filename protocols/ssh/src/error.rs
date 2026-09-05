//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку (`AGENTS.md` §4.2). Неверный пароль или ключ и
//! несовпавший отпечаток хоста повторять бессмысленно — сеть здесь ни при
//! чём, и без вмешательства человека следующая попытка кончится тем же.

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type SshResult<T> = Result<T, SshError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum SshError {
    /// Настройки неверны или противоречивы.
    #[error("настройки SSH: {0}")]
    Config(String),

    /// Сервер не признал пароль или ключ.
    #[error("сервер отклонил опознание: неверный пароль или ключ")]
    AuthRejected,

    /// Ключ, который прислал сервер, не совпал с тем, что записан в настройках.
    ///
    /// Отдельный вариант, а не обрыв связи: молчать об этом означало бы вести
    /// себя как `insecure`, только тихо. Сообщение несёт отпечаток, который
    /// прислал сервер, — по нему видно, обновился ли ключ сервера или это
    /// подмена.
    #[error("отпечаток хоста не совпал: сервер прислал {0}")]
    HostKeyMismatch(String),

    /// Сервер отказался открыть канал `direct-tcpip` до цели.
    #[error("сервер отказал в канале до цели: {0}")]
    ChannelRefused(String),

    /// Соединение оборвалось.
    #[error("соединение потеряно: {0}")]
    Disconnected(String),

    /// Ошибка общего транспорта: срок рукопожатия.
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка библиотеки SSH: рукопожатие, ключевой обмен, протокол.
    #[error("ssh: {0}")]
    Ssh(#[from] russh::Error),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl SshError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Соединение оборвалось.
    pub fn disconnected(message: impl Into<String>) -> Self {
        Self::Disconnected(message.into())
    }
}

impl From<SshError> for ProtocolError {
    fn from(err: SshError) -> Self {
        match err {
            SshError::Config(message) => Self::InvalidConfig(message),
            SshError::AuthRejected => Self::AuthRejected,
            // Не сеть: тот же сервер на том же адресе пришлёт тот же чужой
            // ключ и в следующий раз. Решать может только человек.
            err @ SshError::HostKeyMismatch(_) => Self::InvalidConfig(err.to_string()),
            // Отказ в канале — это ровно «адрес недостижим со стороны
            // сервера», и там уже есть подходящий вариант.
            err @ SshError::ChannelRefused(_) => Self::Unreachable(err.to_string()),
            SshError::Disconnected(message) => Self::Disconnected(message),
            SshError::Transport(err) => err.into(),
            SshError::Ssh(err) => Self::Disconnected(err.to_string()),
            SshError::Io(err) => Self::Io(err),
        }
    }
}

impl From<SshError> for std::io::Error {
    /// Ошибка протокола внутри [`std::io`]: поток отдаёт наружу только его.
    fn from(err: SshError) -> Self {
        match err {
            SshError::Io(err) => err,
            other => Self::other(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrong_password_or_key_is_not_retried() {
        let err: ProtocolError = SshError::AuthRejected.into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_host_key_mismatch_is_not_retried() {
        // Ради этого варианта всё и затевалось: молчать здесь — значит вести
        // себя как `insecure`, только тихо.
        let err: ProtocolError = SshError::HostKeyMismatch("SHA256:чужой".to_owned()).into();
        assert!(!err.is_retryable());
        assert!(err.to_string().contains("SHA256"));
    }

    #[test]
    fn a_channel_refusal_is_retried() {
        // Сервер мог временно не пускать к цели — стоит попробовать ещё раз.
        let err: ProtocolError = SshError::ChannelRefused("порт закрыт".to_owned()).into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = SshError::disconnected("сеть пропала").into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_silent_server_is_retried() {
        let err: ProtocolError = SshError::from(penguin_transport::TransportError::Timeout(
            "рукопожатие SSH",
        ))
        .into();
        assert!(err.is_retryable());
    }
}
