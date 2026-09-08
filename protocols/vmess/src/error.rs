//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку (`AGENTS.md` §4.2).
//!
//! # Про `AuthRejected` и молчание
//!
//! У VMess, в отличие от VLESS и Trojan, отказ иногда всё-таки виден: сервер,
//! не нашедший подходящего опознавателя заголовка ни у одного известного ему
//! пользователя, закрывает соединение молча — это [`VmessError::Disconnected`], как
//! и у соседей. Но если опознаватель совпал (то есть UUID верный) и заголовок
//! ответа расшифровался, а первый байт в нём не совпадает с байтом, который
//! отправили мы, — это уже не сеть и не порча, а [`VmessError::AuthRejected`]:
//! сервер отвечает, но не тем, о чём договаривались.

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type VmessResult<T> = Result<T, VmessError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum VmessError {
    /// Настройки неверны или противоречивы.
    #[error("настройки VMess: {0}")]
    Config(String),

    /// Сервер ответил не по протоколу.
    #[error("ответ не по протоколу: {0}")]
    Malformed(String),

    /// Байт проверки в ответе не совпал с тем, что отправил клиент.
    ///
    /// Заголовок ответа расшифровался — значит, ключи совпали и UUID сервер
    /// принял. Несовпадение здесь означает не порчу по дороге (AEAD такую бы
    /// не пропустил), а сервер, отвечающий не так, как договаривались.
    #[error("сервер VMess ответил, но байт проверки не совпал")]
    AuthRejected,

    /// Датаграмма или кусок тела не помещаются в объявляемую длину.
    #[error("данные в {0} байт длиннее, чем допускает кадр VMess")]
    Oversized(usize),

    /// Проксирование UDP выключено в настройках профиля.
    #[error("проксирование UDP выключено в настройках профиля")]
    UdpDisabled,

    /// Соединение оборвалось.
    ///
    /// Сюда же попадает неверный UUID: сервер, не нашедший подходящего
    /// опознавателя, закрывает соединение молча — как и у VLESS с Trojan.
    /// Расхождение часов больше чем на 120 секунд (`proxy/vmess/aead`,
    /// `AuthIDDecoderHolder.Match`, эталон `v2fly/v2ray-core`) сервер
    /// отвергает тем же способом: если дело в часах, поправьте их и
    /// проверьте UUID отдельно.
    #[error(
        "соединение потеряно: {0} — если сервер молчит с самого начала, проверьте UUID и \
         разницу часов с сервером: VMess отвергает расхождение больше 120 секунд тем же \
         молчанием"
    )]
    Disconnected(String),

    /// Ошибка общего транспорта: TLS, WebSocket, срок рукопожатия, адрес.
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl VmessError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Сервер ответил не по протоколу.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }
}

impl From<VmessError> for ProtocolError {
    fn from(err: VmessError) -> Self {
        match err {
            VmessError::Config(message) => Self::InvalidConfig(message),
            err @ VmessError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            VmessError::AuthRejected => Self::AuthRejected,
            err @ VmessError::Oversized(_) => Self::InvalidConfig(err.to_string()),
            VmessError::UdpDisabled => Self::Unsupported("UDP"),
            VmessError::Disconnected(message) => Self::Disconnected(message),
            VmessError::Transport(err) => err.into(),
            VmessError::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = VmessError::Disconnected("сеть пропала".into()).into();
        assert!(err.is_retryable());
    }

    #[test]
    fn auth_rejected_is_not_retried() {
        let err: ProtocolError = VmessError::AuthRejected.into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn the_wrong_kind_of_server_is_not_retried() {
        let err: ProtocolError = VmessError::malformed("версия ответа 0x02").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn disconnected_names_the_clock_and_the_uuid() {
        let err = VmessError::Disconnected("тест".to_owned());
        assert!(err.to_string().contains("120"));
        assert!(err.to_string().contains("UUID"));
    }
}
