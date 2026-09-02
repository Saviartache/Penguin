//! Ошибки движка.
//!
//! Движок — единственное место, где сходятся ошибки всех слоёв: протокола,
//! правил, адаптера, платформы. Он же переводит их в то, что можно показать
//! пользователю, и решает, что делать дальше.

use thiserror::Error;

/// Результат работы движка.
pub type EngineResult<T> = Result<T, EngineError>;

/// Что помешало.
#[derive(Debug, Error)]
pub enum EngineError {
    /// В настройках нет ни одного профиля.
    #[error("не задано ни одного профиля — подключаться некуда")]
    NoProfiles,

    /// Профиль с таким именем не найден.
    #[error("нет профиля `{0}`")]
    NoSuchProfile(String),

    /// Правила не собираются.
    #[error(transparent)]
    Router(#[from] penguin_router::error::RouterError),

    /// Протокол не поднялся.
    #[error(transparent)]
    Protocol(#[from] penguin_proto::error::ProtocolError),

    /// Адаптер не открылся.
    #[error(transparent)]
    Tun(#[from] penguin_tun::TunError),

    /// Система не дала сделать то, что нужно тоннелю.
    #[error(transparent)]
    Platform(#[from] penguin_platform::PlatformError),

    /// DNS не настроился.
    #[error(transparent)]
    Dns(#[from] penguin_dns::DnsError),

    /// Входящая точка не поднялась.
    #[error(transparent)]
    Inbound(#[from] penguin_inbound::InboundError),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl EngineError {
    /// Нужно ли пользователю что-то сделать, прежде чем повторять.
    ///
    /// По этому признаку интерфейс решает, показывать ли «переподключаюсь»
    /// или «исправьте настройки и попробуйте снова».
    pub fn needs_user_action(&self) -> bool {
        match self {
            Self::NoProfiles | Self::NoSuchProfile(_) | Self::Router(_) => true,
            Self::Protocol(err) => !err.is_retryable(),
            Self::Tun(err) => err.needs_user_action(),
            Self::Platform(err) => err.needs_privileges(),
            Self::Dns(_) | Self::Inbound(_) | Self::Io(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use penguin_proto::error::ProtocolError;

    use super::*;

    #[test]
    fn config_problems_need_the_user() {
        assert!(EngineError::NoProfiles.needs_user_action());
        assert!(EngineError::NoSuchProfile("home".into()).needs_user_action());
    }

    #[test]
    fn wrong_password_needs_the_user() {
        // Показывать «переподключаюсь» при неверном пароле — значит врать.
        assert!(EngineError::Protocol(ProtocolError::AuthRejected).needs_user_action());
    }

    #[test]
    fn network_failures_do_not() {
        let err = EngineError::Protocol(ProtocolError::Disconnected("сеть".into()));
        assert!(!err.needs_user_action());
    }

    #[test]
    fn missing_driver_needs_the_user() {
        let missing = penguin_tun::TunError::driver_missing(std::path::Path::new("C:/penguin"));
        assert!(EngineError::Tun(missing).needs_user_action());
    }
}
