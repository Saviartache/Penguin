//! Ошибки протокола.
//!
//! Различие между вариантами не косметическое: по нему `supervisor` решает,
//! повторять ли попытку (`AGENTS.md` §4.2).
//!
//! # Про `AuthRejected` и часы
//!
//! Отдельного варианта для неверного пароля здесь нет — не потому, что мы его
//! не различаем, а потому, что сервер эталона в буквальном смысле не может его
//! сообщить. Первый ответ сервера — это его собственный нонс, двенадцать байт
//! (`streamserver.go`). Он уходит клиенту **после** того, как сервер успешно
//! расшифровал первый кусок клиента и проверил метку времени; если пароль не
//! тот или часы разошлись больше чем на минуту, сервер возвращается с ошибкой
//! до этой записи и просто закрывает соединение. Клиент в обоих случаях видит
//! одно и то же: поток оборвался, не дождавшись двенадцати байт.
//!
//! Разнести эти две причины по разным вариантам значило бы гадать. Вместо
//! этого есть один вариант, [`BrookError::HandshakeRejected`], и его текст
//! называет обе причины прямо — включая часы, как того требует чувствительность
//! протокола к времени (см. документ [`crate`]).

use penguin_proto::error::ProtocolError;
use thiserror::Error;

/// Результат операции протокола.
pub type BrookResult<T> = Result<T, BrookError>;

/// Что пошло не так.
#[derive(Debug, Error)]
pub enum BrookError {
    /// Настройки неверны или противоречивы.
    #[error("настройки Brook: {0}")]
    Config(String),

    /// Сервер не прислал свой нонс: рукопожатие оборвалось до ответа.
    ///
    /// Единственная причина, которую эталон умеет сообщить сам, — молчание.
    /// Он закрывает соединение и тогда, когда пароль не совпал, и тогда, когда
    /// метка времени в запросе отстала от часов сервера больше чем на
    /// [`crate::frame::tcp::CLOCK_TOLERANCE_SECS`] секунд. Различить эти два
    /// случая по одному закрытому сокету нельзя.
    #[error(
        "сервер Brook не ответил на рукопожатие: либо неверный пароль, либо часы этого \
         устройства отстают от часов сервера больше чем на 60 секунд — проверьте оба"
    )]
    HandshakeRejected,

    /// Метка подлинности не сошлась на уже идущем соединении.
    ///
    /// В отличие от [`Self::HandshakeRejected`] это не первый ответ сервера, а
    /// кусок посреди потока: либо порча по дороге, либо кто-то другой ответил
    /// не тем ключом. Продолжать нельзя ни в одном из случаев.
    #[error("метка подлинности не сошлась: данные испорчены или подделаны")]
    Rejected,

    /// Поток или датаграмма разъехались с форматом.
    #[error("не по протоколу Brook: {0}")]
    Malformed(String),

    /// Кусок длиннее, чем допускает кадр или буфер настоящего сервера.
    #[error("кусок в {0} байт: сервер Brook не примет больше 2014 байт за один кусок")]
    Oversized(usize),

    /// Не удалось получить ключевой материал.
    #[error("вывод ключа Brook: {0}")]
    Crypto(String),

    /// Проксирование UDP выключено в настройках профиля или недоступно в
    /// выбранном режиме транспорта.
    #[error("проксирование UDP выключено в настройках профиля")]
    UdpDisabled,

    /// Соединение оборвалось.
    #[error("соединение потеряно: {0}")]
    Disconnected(String),

    /// Ошибка общего транспорта: WebSocket, TLS, срок рукопожатия, адрес.
    #[error(transparent)]
    Transport(#[from] penguin_transport::TransportError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl BrookError {
    /// Ошибка настроек.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Поток или датаграмма разъехались с форматом.
    pub fn malformed(message: impl Into<String>) -> Self {
        Self::Malformed(message.into())
    }

    /// Обрыв соединения.
    pub fn disconnected(message: impl Into<String>) -> Self {
        Self::Disconnected(message.into())
    }

    /// Не вывелся ключевой материал.
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto(message.into())
    }
}

impl From<BrookError> for ProtocolError {
    fn from(err: BrookError) -> Self {
        match err {
            BrookError::Config(message) => Self::InvalidConfig(message),
            // Оба варианта отказа не лечатся повторной попыткой: пароль сам
            // не исправится, а часы за секунды до следующей попытки — тоже.
            BrookError::HandshakeRejected => Self::AuthRejected,
            err @ BrookError::Rejected => Self::Disconnected(err.to_string()),
            err @ BrookError::Malformed(_) => Self::InvalidConfig(err.to_string()),
            err @ BrookError::Oversized(_) => Self::InvalidConfig(err.to_string()),
            err @ BrookError::Crypto(_) => Self::InvalidConfig(err.to_string()),
            BrookError::UdpDisabled => Self::Unsupported("UDP"),
            BrookError::Disconnected(message) => Self::Disconnected(message),
            BrookError::Transport(err) => err.into(),
            BrookError::Io(err) => Self::Io(err),
        }
    }
}

impl From<BrookError> for std::io::Error {
    /// Ошибка протокола внутри [`std::io`]: поток отдаёт наружу только его.
    fn from(err: BrookError) -> Self {
        match err {
            BrookError::Io(err) => err,
            other => Self::other(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handshake_rejection_is_not_retried() {
        // Повторять с тем же паролем и теми же часами бессмысленно — обе
        // причины сами собой не пройдут.
        let err: ProtocolError = BrookError::HandshakeRejected.into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn the_error_names_the_clock_explicitly() {
        // Требование не косметическое: расхождение часов для человека
        // выглядит как сломанная сеть, и текст обязан назвать эту причину
        // прямо, а не только «сервер не ответил».
        let text = BrookError::HandshakeRejected.to_string();
        assert!(text.contains("часы"), "{text}");

        // Число в тексте написано literal-ом; тест ловит расхождение с
        // константой, если её когда-нибудь поправят, а текст — забудут.
        let tolerance = crate::frame::tcp::CLOCK_TOLERANCE_SECS.to_string();
        assert!(text.contains(&tolerance), "{text}");
    }

    #[test]
    fn the_oversized_message_matches_the_real_limit() {
        let text = BrookError::Oversized(9999).to_string();
        let limit = crate::frame::tcp::MAX_PAYLOAD.to_string();
        assert!(text.contains(&limit), "{text}");
    }

    #[test]
    fn a_mid_stream_tag_mismatch_is_disconnected_not_auth_rejected() {
        // Это не первый ответ сервера, а порча на уже идущем канале: сама
        // категория другая, хотя причина в проводе похожая.
        let err: ProtocolError = BrookError::Rejected.into();
        assert!(!matches!(err, ProtocolError::AuthRejected));
    }

    #[test]
    fn a_broken_link_is_retried() {
        let err: ProtocolError = BrookError::disconnected("сеть пропала").into();
        assert!(err.is_retryable());
    }

    #[test]
    fn udp_turned_off_is_not_a_failure_to_retry() {
        let err: ProtocolError = BrookError::UdpDisabled.into();
        assert!(!err.is_retryable());
    }

    #[test]
    fn a_silent_server_is_retried() {
        let err: ProtocolError = BrookError::from(penguin_transport::TransportError::Timeout(
            "рукопожатие Brook",
        ))
        .into();
        assert!(err.is_retryable());
    }
}
