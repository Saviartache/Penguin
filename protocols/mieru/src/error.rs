//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку (`AGENTS.md` §4.2).
//!
//! Одного варианта здесь нет и быть не может — `AuthRejected`. Ключ Mieru
//! выводится из имени пользователя и пароля, и сервер узнаёт своего не по
//! отдельному сообщению, а по тому, нашёлся ли пользователь, чей ключ
//! расшифровывает первый кусок. Не нашёлся — сервер молча не отвечает или
//! закрывает соединение: ответить осмысленно означало бы подтвердить, что
//! перебор пользователя был близок к успеху. С той стороны клиента это
//! неотличимо от обрыва сети, ровно как у AnyTLS и Trojan (см. документ
//! крейта).

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type MieruResult<T> = Result<T, MieruError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum MieruError {
    /// Настройки неверны или противоречивы.
    #[error("настройки Mieru: {0}")]
    Config(String),

    /// Сегмент не по формату: неизвестный тип, неверная длина, чужой протокол.
    #[error("сегмент Mieru не по формату: {0}")]
    Malformed(String),

    /// Метка подлинности не сошлась.
    ///
    /// Не обязательно неверный пароль: с той же вероятностью это ответ не
    /// того сервера или урезанное соединение. Различить нельзя — см. документ
    /// модуля.
    #[error("метка подлинности сегмента Mieru не сошлась")]
    Rejected,

    /// Отметка времени в сегменте разошлась с часами дальше допустимого.
    ///
    /// Ключ Mieru зависит от системного времени (см. `keying`), и рассинхрон
    /// часов выглядит как молчание сервера, а не как понятная ошибка. Текст
    /// называет это прямо, а не даёт дойти до общего `Disconnected`.
    #[error(
        "метка времени сегмента Mieru разошлась с часами больше чем на минуту: \
         проверьте синхронизацию времени на этой машине"
    )]
    ClockSkew,

    /// Сервер ответил, что квота исчерпана.
    #[error("сервер Mieru отказал: исчерпана квота")]
    QuotaExhausted,

    /// Сессия закрылась или не открылась.
    #[error("сессия Mieru потеряна: {0}")]
    Disconnected(String),

    /// Проксирование UDP не реализовано.
    #[error("проксирование UDP через Mieru не реализовано в этой сборке")]
    UdpUnsupported,

    /// Сервер изнутри туннеля отказал в подключении к цели.
    #[error("сервер Mieru не смог подключиться к цели: {0}")]
    Unreachable(String),

    /// Ошибка общего транспорта: срок рукопожатия, адрес.
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl MieruError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Сегмент не по формату.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }

    /// Сессия потеряна.
    pub fn disconnected(message: impl Into<String>) -> Self {
        Self::Disconnected(message.into())
    }

    /// Сервер не смог подключиться к цели.
    pub fn unreachable(message: impl Into<String>) -> Self {
        Self::Unreachable(message.into())
    }
}

impl From<MieruError> for ProtocolError {
    fn from(err: MieruError) -> Self {
        match err {
            MieruError::Config(message) => Self::InvalidConfig(message),
            // Разъехавшийся формат — это не сеть: пока на том конце не тот
            // сервер, повторять нечего.
            err @ MieruError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            // Не сошедшаяся метка — либо чужой сервер, либо порча по дороге.
            // Оба раза продолжать нельзя, но и залипать в бесконечных
            // повторах ошибки настроек не стоит: сеть могла и вправду
            // испортить один пакет.
            err @ MieruError::Rejected => Self::Disconnected(err.to_string()),
            err @ MieruError::ClockSkew => Self::Disconnected(err.to_string()),
            err @ MieruError::QuotaExhausted => Self::Disconnected(err.to_string()),
            MieruError::Disconnected(message) => Self::Disconnected(message),
            MieruError::UdpUnsupported => Self::Unsupported("UDP"),
            err @ MieruError::Unreachable(_) => Self::Unreachable(err.to_string()),
            MieruError::Transport(err) => err.into(),
            MieruError::Io(err) => Self::Io(err),
        }
    }
}

impl From<MieruError> for std::io::Error {
    /// Ошибка протокола внутри [`std::io`]: поток отдаёт наружу только его.
    fn from(err: MieruError) -> Self {
        match err {
            MieruError::Io(err) => err,
            other => Self::other(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = MieruError::disconnected("сеть пропала").into();
        assert!(err.is_retryable());
    }

    #[test]
    fn the_wrong_kind_of_server_is_not_retried() {
        let err: ProtocolError = MieruError::malformed("неизвестный тип протокола").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_tag_mismatch_is_retried_and_not_blamed_on_settings() {
        // Не сошедшаяся метка не обязательно значит неверный пароль: сеть
        // могла испортить один пакет, и настройки в этом не виноваты.
        let err: ProtocolError = MieruError::Rejected.into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_silent_server_is_retried() {
        let err: ProtocolError = MieruError::from(penguin_transport::TransportError::Timeout(
            "открытие сессии Mieru",
        ))
        .into();
        assert!(err.is_retryable());
    }

    #[test]
    fn udp_turned_off_is_not_a_failure_to_retry() {
        let err: ProtocolError = MieruError::UdpUnsupported.into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn an_unreachable_target_is_named_as_such() {
        let err: ProtocolError = MieruError::unreachable("connection refused").into();
        assert!(matches!(err, ProtocolError::Unreachable(_)));
    }

    #[test]
    fn the_clock_skew_error_names_the_cause() {
        let err: ProtocolError = MieruError::ClockSkew.into();
        assert!(err.to_string().contains("врем"), "{err}");
    }

    #[test]
    fn an_io_error_stays_itself_on_the_way_out() {
        let err = std::io::Error::new(std::io::ErrorKind::WouldBlock, "занято");
        let back: std::io::Error = MieruError::Io(err).into();
        assert_eq!(back.kind(), std::io::ErrorKind::WouldBlock);
    }
}
