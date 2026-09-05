//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку (`AGENTS.md` §4.2). У OpenConnect, в отличие от
//! Trojan, сервер отвечает на неверный пароль явно — `401` с пустым телом
//! (`ocserv`, `src/worker-auth.c`), — поэтому `AuthRejected` здесь настоящий,
//! а не общий случай молчания.

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type OpenConnectResult<T> = Result<T, OpenConnectError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum OpenConnectError {
    /// Настройки неверны или противоречивы.
    #[error("настройки OpenConnect: {0}")]
    Config(String),

    /// Сервер ответил `401`/`403`: неверные имя или пароль. Повторять
    /// бессмысленно тем же паролем.
    #[error("сервер отклонил имя или пароль")]
    AuthRejected,

    /// Сервер запросил при входе то, что не сводится к имени и паролю:
    /// одноразовый код, второй, отдельный пароль, выбор из формы, которую
    /// заполнить нечем. Строка — подсказка поля так, как её прислал сервер.
    #[error("сервер запросил дополнительный шаг входа: {0}")]
    SecondFactorRequired(String),

    /// Обмен HTTPS/XML не сошёлся с ожидаемым форматом: не тот код ответа,
    /// разъехавшийся XML, форма без полей, которые можно понять.
    #[error("ответ сервера не по протоколу OpenConnect: {0}")]
    Malformed(String),

    /// Кадр CSTP пришёл не по формату (`STF\x01`, длина, тип).
    #[error("кадр CSTP не по формату: {0}")]
    Frame(String),

    /// Соединение оборвалось.
    #[error("соединение потеряно: {0}")]
    Disconnected(String),

    /// Ошибка общего транспорта: TLS, срок рукопожатия.
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl OpenConnectError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Ответ не по протоколу.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }

    /// Кадр не по формату.
    pub fn frame(message: impl Into<String>) -> Self {
        Self::Frame(message.into())
    }

    /// Обрыв соединения.
    pub fn disconnected(message: impl Into<String>) -> Self {
        Self::Disconnected(message.into())
    }
}

impl From<OpenConnectError> for ProtocolError {
    fn from(err: OpenConnectError) -> Self {
        match err {
            OpenConnectError::Config(message) => Self::InvalidConfig(message),
            OpenConnectError::AuthRejected => Self::AuthRejected,
            // Отдельного варианта под второй фактор в общем языке нет: с
            // точки зрения `supervisor` это тоже «повторять бессмысленно, пока
            // человек не сменит настройки», — но текст обязан назвать, что
            // именно спросил сервер, а не свестись к «неверный пароль».
            err @ OpenConnectError::SecondFactorRequired(_) => Self::InvalidConfig(err.to_string()),
            err @ OpenConnectError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            err @ OpenConnectError::Frame(_) => Self::InvalidConfig(err.to_string()),
            OpenConnectError::Disconnected(message) => Self::Disconnected(message),
            OpenConnectError::Transport(err) => err.into(),
            OpenConnectError::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrong_password_is_not_retried() {
        let err: ProtocolError = OpenConnectError::AuthRejected.into();
        assert!(!err.is_retryable());
        assert!(matches!(err, ProtocolError::AuthRejected));
    }

    #[test]
    fn a_server_asking_for_a_second_factor_says_so() {
        // Не `AuthRejected`: пароль сервер как раз принял, а спросил третье.
        let err: ProtocolError =
            OpenConnectError::SecondFactorRequired("Одноразовый код:".to_owned()).into();
        assert!(!err.is_retryable());
        assert!(err.to_string().contains("Одноразовый код:"), "{err}");
    }

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = OpenConnectError::disconnected("сеть пропала").into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_bad_frame_is_not_a_reason_to_retry() {
        // Пока на том конце не CSTP, следующая попытка кончится тем же.
        let err: ProtocolError = OpenConnectError::frame("нет магии STF").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_silent_server_is_retried() {
        let err: ProtocolError = OpenConnectError::from(
            penguin_transport::TransportError::Timeout("рукопожатие TLS"),
        )
        .into();
        assert!(err.is_retryable());
    }
}
