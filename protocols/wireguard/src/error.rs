//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку (`AGENTS.md` §4.2).
//!
//! `AuthRejected` здесь — это не то, что кажется на первый взгляд. WireGuard
//! не присылает отказ: чужой ключ выглядит как молчание, неотличимое от
//! потерянной сети (`man 8 wg` и сама спецификация не описывают код ошибки
//! опознания вообще). Отличить одно от другого клиент не может — а значит и
//! не должен: единственный способ, которым локальная сторона узнаёт про
//! заведомо чужой ключ, — сверить его **до** попытки подключения, в
//! [`crate::config::WireguardConfig::validate`]. После этого шага всё, что
//! происходит на проводе, — это уже вопрос сети, и `AuthRejected` этот крейт
//! никогда не возвращает: возвращать код специально ради него — как раз то
//! неотличимое от домысла, о котором предупреждает план.
use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type WireguardResult<T> = Result<T, WireguardError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum WireguardError {
    /// Настройки неверны или противоречивы.
    #[error("настройки WireGuard: {0}")]
    Config(String),

    /// Пакет или сообщение рукопожатия не по формату либо не прошли
    /// проверку подлинности.
    ///
    /// Оба случая неотличимы друг от друга по самому факту отказа AEAD, и не
    /// нужно их различать: реакция одна — отбросить и не повторять с теми же
    /// ключами.
    #[error("пакет не по протоколу: {0}")]
    Malformed(String),

    /// Рукопожатие не уложилось в срок: сервер не ответил.
    #[error("рукопожатие WireGuard не уложилось в срок")]
    HandshakeTimeout,

    /// Сеанс истёк: ни разу не удалось обновить рукопожатие вовремя.
    #[error("сеанс WireGuard истёк: рукопожатие не обновилось за {0:?}")]
    SessionExpired(std::time::Duration),

    /// Направление закрыто, и труба для пакетов больше не работает.
    ///
    /// `close()` вызывает сам движок при остановке профиля — в нормальной
    /// работе этот вариант никому не виден. Если он всё же дошёл до
    /// `send`/`recv`, для того, кто их позвал, это неотличимо от обрыва
    /// связи, и реакция та же: отдать ошибку, а не притвориться, что пакет
    /// ушёл.
    #[error("направление WireGuard закрыто")]
    Closed,

    /// Сеть подвела: адрес не разрешился, сокет не открылся, соединение
    /// пропало не на уровне рукопожатия и не на уровне сеанса.
    #[error("сеть WireGuard: {0}")]
    Disconnected(String),

    /// Ошибка ввода-вывода на сокете.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl WireguardError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Пакет не по формату.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }

    /// Сеть подвела.
    pub fn disconnected(message: impl Into<String>) -> Self {
        Self::Disconnected(message.into())
    }
}

impl From<WireguardError> for ProtocolError {
    fn from(err: WireguardError) -> Self {
        match err {
            WireguardError::Config(message) => Self::InvalidConfig(message),
            // Разъехавшийся пакет — это либо чужой ключ, либо порча на
            // проводе; ни то ни другое само не пройдёт при повторе с теми же
            // ключами.
            err @ WireguardError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            err @ WireguardError::HandshakeTimeout => Self::Disconnected(err.to_string()),
            err @ WireguardError::SessionExpired(_) => Self::Disconnected(err.to_string()),
            err @ WireguardError::Closed => Self::Disconnected(err.to_string()),
            WireguardError::Disconnected(message) => Self::Disconnected(message),
            WireguardError::Io(err) => Self::Io(err),
        }
    }
}

impl From<penguin_transport::TransportError> for WireguardError {
    /// Переводит общую ошибку транспорта (используется здесь только ради
    /// `deadline::handshake` — срока на рукопожатие) на язык этого крейта.
    ///
    /// На практике из всех вариантов встречается только `Timeout`: остальные
    /// эта реализация не производит сама, но перевод обязан быть полным —
    /// `deadline::within` требует `E: From<TransportError>` целиком, а не
    /// один вариант.
    fn from(err: penguin_transport::TransportError) -> Self {
        use penguin_transport::TransportError as E;
        match err {
            E::Timeout(_) => Self::HandshakeTimeout,
            E::Config(message) => Self::Config(message),
            E::Address(message) | E::Malformed(message) => Self::Malformed(message),
            E::Rejected => Self::Malformed(err.to_string()),
            E::Disconnected(message) => Self::Disconnected(message),
            E::Io(err) => Self::Io(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_broken_config_is_not_retried() {
        let err: ProtocolError = WireguardError::config("пустой ключ").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_malformed_packet_is_not_retried() {
        // Пока на проводе не то, что настроено (чужой ключ, порча), само
        // оно не изменится.
        let err: ProtocolError = WireguardError::malformed("метка не сошлась").into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_handshake_timeout_is_retried() {
        // Молчащий сервер — это сеть, а не настройки: обязательно повторить.
        let err: ProtocolError = WireguardError::HandshakeTimeout.into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_dead_session_is_retried() {
        let err: ProtocolError =
            WireguardError::SessionExpired(std::time::Duration::from_secs(180)).into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_closed_outbound_is_retried() {
        // `close()` вызывает сам движок при остановке профиля; появление
        // этой ошибки в другом месте означает обрыв, а не намеренный отказ.
        let err: ProtocolError = WireguardError::Closed.into();
        assert!(err.is_retryable());
    }

    #[test]
    fn an_io_error_is_retried() {
        let io = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        let err: ProtocolError = WireguardError::from(io).into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_resolve_failure_is_retried() {
        // Адрес не разрешился — это сеть (DNS сейчас недоступен), а не
        // настройки (имя может быть верным).
        let err: ProtocolError = WireguardError::disconnected("example.com: не отвечает").into();
        assert!(err.is_retryable());
    }

    #[test]
    fn a_transport_timeout_becomes_a_handshake_timeout() {
        let err = WireguardError::from(penguin_transport::TransportError::Timeout(
            "рукопожатие WireGuard",
        ));
        assert!(matches!(err, WireguardError::HandshakeTimeout));
    }
}
