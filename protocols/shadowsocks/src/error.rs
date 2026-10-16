//! Ошибки протокола; по варианту `supervisor` решает, повторять ли (AGENTS §4.2).

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type ShadowsocksResult<T> = Result<T, ShadowsocksError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum ShadowsocksError {
    /// Настройки неверны или противоречивы.
    #[error("настройки Shadowsocks: {0}")]
    Config(String),

    /// Метода с таким именем нет.
    #[error("неизвестный метод шифрования `{0}`")]
    UnknownMethod(String),

    /// Метка подлинности не сошлась: так выглядит неверный пароль, повтор бессмысленен.
    #[error("не сходится метка подлинности: почти всегда это неверный пароль или метод")]
    Rejected,

    /// Ошибка внутри шифра.
    #[error("шифрование: {0}")]
    Crypto(String),

    /// Сервер прислал не то, что позволяет протокол.
    #[error("поток не по протоколу: {0}")]
    Malformed(String),

    /// Метка времени 2022 разошлась с часами больше чем на 30 с (ключ при этом верный).
    #[error(
        "метка времени Shadowsocks 2022 разошлась с часами этого устройства на {0} с \
         (сервер отвергает то, что больше 30 с) — проверьте системное время"
    )]
    ClockSkew(u64),

    /// Проксирование UDP выключено в настройках профиля.
    #[error("проксирование UDP выключено в настройках профиля")]
    UdpDisabled,

    /// Соединение оборвалось.
    #[error("соединение потеряно: {0}")]
    Disconnected(String),

    /// Ошибка общего транспорта: запись адреса, срок рукопожатия.
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl ShadowsocksError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Ошибка шифра.
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto(message.into())
    }

    /// Сервер прислал не то.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }
}

impl From<ShadowsocksError> for ProtocolError {
    fn from(err: ShadowsocksError) -> Self {
        match err {
            ShadowsocksError::Config(message) => Self::InvalidConfig(message),
            err @ ShadowsocksError::UnknownMethod(_) => Self::InvalidConfig(err.to_string()),
            ShadowsocksError::Rejected => Self::AuthRejected,
            err @ ShadowsocksError::Crypto(_) => Self::InvalidConfig(err.to_string()),
            err @ ShadowsocksError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            err @ ShadowsocksError::ClockSkew(_) => Self::Disconnected(err.to_string()),
            ShadowsocksError::UdpDisabled => Self::Unsupported("UDP"),
            ShadowsocksError::Disconnected(message) => Self::Disconnected(message),
            ShadowsocksError::Transport(err) => err.into(),
            ShadowsocksError::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrong_password_is_not_retried() {
        let err: ProtocolError = ShadowsocksError::Rejected.into();
        assert!(!err.is_retryable());
        assert!(matches!(err, ProtocolError::AuthRejected));
    }

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = ShadowsocksError::Disconnected("сеть пропала".into()).into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_clock_skew_names_the_seconds_and_is_retried() {
        let err: ProtocolError = ShadowsocksError::ClockSkew(42).into();
        assert!(err.is_retryable());
        assert!(err.to_string().contains("42"), "{err}");
        assert!(err.to_string().to_lowercase().contains("час"), "{err}");
    }

    #[test]
    fn an_unknown_method_names_itself() {
        let err: ProtocolError = ShadowsocksError::UnknownMethod("rc4-md5".into()).into();
        assert!(err.to_string().contains("rc4-md5"), "{err}");
        assert!(!err.is_retryable());
    }
}
