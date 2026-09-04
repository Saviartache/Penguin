//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку (`AGENTS.md` §4.2).

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
    ///
    /// Отдельным вариантом ради текста: «неверные настройки» без имени метода
    /// не отвечают на вопрос, что именно исправить.
    #[error("неизвестный метод шифрования `{0}`")]
    UnknownMethod(String),

    /// Метка подлинности не сошлась.
    ///
    /// У Shadowsocks нет ни рукопожатия, ни ответа об отказе: сервер, не
    /// сумевший расшифровать первый кусок, просто закрывает соединение. Со
    /// стороны клиента неверный пароль выглядит именно так — как не сошедшаяся
    /// метка, — и повторять с ним бессмысленно.
    #[error("не сходится метка подлинности: почти всегда это неверный пароль или метод")]
    Rejected,

    /// Ошибка внутри шифра.
    #[error("шифрование: {0}")]
    Crypto(String),

    /// Сервер прислал не то, что позволяет протокол.
    #[error("поток не по протоколу: {0}")]
    Malformed(String),

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
            // Неверный пароль повторять бессмысленно: он не изменится сам.
            ShadowsocksError::Rejected => Self::AuthRejected,
            err @ ShadowsocksError::Crypto(_) => Self::InvalidConfig(err.to_string()),
            err @ ShadowsocksError::Malformed(_) => Self::InvalidConfig(err.to_string()),
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
        // У Shadowsocks отказ приходит именно так: метка не сошлась.
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
    fn an_unknown_method_names_itself() {
        let err: ProtocolError = ShadowsocksError::UnknownMethod("rc4-md5".into()).into();
        assert!(err.to_string().contains("rc4-md5"), "{err}");
        assert!(!err.is_retryable());
    }
}
