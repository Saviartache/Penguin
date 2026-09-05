//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку (`AGENTS.md` §4.2).

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type ShadowsocksrResult<T> = Result<T, ShadowsocksrError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum ShadowsocksrError {
    /// Настройки неверны или противоречивы.
    #[error("настройки ShadowsocksR: {0}")]
    Config(String),

    /// Метода шифрования с таким именем нет или он не реализован.
    #[error("неизвестный или нереализованный метод шифрования `{0}`")]
    UnknownMethod(String),

    /// Надстройки `obfs` с таким именем нет или она не реализована.
    #[error("неизвестная или нереализованная надстройка obfs `{0}`")]
    UnknownObfs(String),

    /// Надстройки `protocol` с таким именем нет или она не реализована.
    #[error("неизвестная или нереализованная надстройка protocol `{0}`")]
    UnknownProtocol(String),

    /// Метка подлинности не сошлась — почти всегда неверный пароль.
    ///
    /// У `origin`/`plain` отказа как такового нет: сервер с другим паролем
    /// расшифрует наш заголовок в мусор и промолчит, что для клиента
    /// выглядит обрывом соединения. У `auth_*` есть настоящая проверка HMAC,
    /// и именно её провал приходит сюда осмысленно.
    #[error("не сходится метка подлинности: почти всегда это неверный пароль")]
    Rejected,

    /// Ошибка внутри шифра или надстройки протокола.
    #[error("шифрование: {0}")]
    Crypto(String),

    /// Сервер прислал не то, что позволяет протокол.
    #[error("поток не по протоколу: {0}")]
    Malformed(String),

    /// Проксирование UDP выключено в настройках профиля.
    #[error("проксирование UDP выключено в настройках профиля")]
    UdpDisabled,

    /// UDP не реализован в этой версии крейта.
    #[error("UDP для ShadowsocksR пока не реализован")]
    UdpUnimplemented,

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

impl ShadowsocksrError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Ошибка шифра или надстройки.
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto(message.into())
    }

    /// Сервер прислал не то.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }
}

impl From<ShadowsocksrError> for ProtocolError {
    fn from(err: ShadowsocksrError) -> Self {
        match err {
            ShadowsocksrError::Config(message) => Self::InvalidConfig(message),
            err @ ShadowsocksrError::UnknownMethod(_) => Self::InvalidConfig(err.to_string()),
            err @ ShadowsocksrError::UnknownObfs(_) => Self::InvalidConfig(err.to_string()),
            err @ ShadowsocksrError::UnknownProtocol(_) => Self::InvalidConfig(err.to_string()),
            // Неверный пароль повторять бессмысленно: он не изменится сам.
            ShadowsocksrError::Rejected => Self::AuthRejected,
            err @ ShadowsocksrError::Crypto(_) => Self::InvalidConfig(err.to_string()),
            err @ ShadowsocksrError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            ShadowsocksrError::UdpDisabled => Self::Unsupported("UDP"),
            ShadowsocksrError::UdpUnimplemented => Self::Unsupported("UDP"),
            ShadowsocksrError::Disconnected(message) => Self::Disconnected(message),
            ShadowsocksrError::Transport(err) => err.into(),
            ShadowsocksrError::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rejected_auth_tag_is_not_retried() {
        // HMAC не сошёлся — почти всегда неверный пароль, и он не изменится
        // сам собой при повторной попытке.
        let err: ProtocolError = ShadowsocksrError::Rejected.into();
        assert!(!err.is_retryable());
        assert!(matches!(err, ProtocolError::AuthRejected));
    }

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = ShadowsocksrError::Disconnected("сеть пропала".into()).into();
        assert!(err.is_retryable());
    }

    #[test]
    fn an_unknown_method_names_itself() {
        let err: ProtocolError = ShadowsocksrError::UnknownMethod("idea-cfb".into()).into();
        assert!(err.to_string().contains("idea-cfb"), "{err}");
        assert!(!err.is_retryable());
    }

    #[test]
    fn an_unimplemented_obfs_is_a_config_error_not_a_silent_pass() {
        // Опечатка или недоделанная надстройка обязаны дать понятную ошибку
        // из `validate()`, а не молчащее соединение (см. документ крейта).
        let err: ProtocolError = ShadowsocksrError::UnknownObfs("tls1.2_ticket_auth".into()).into();
        assert!(matches!(err, ProtocolError::InvalidConfig(_)));
    }
}
