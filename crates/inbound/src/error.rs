//! Ошибки входящих точек.

use thiserror::Error;

/// Результат работы входящей точки.
pub type InboundResult<T> = Result<T, InboundError>;

/// Что пошло не так на стороне приложения.
///
/// Отделено от ошибок протокола намеренно: здесь ломается разговор с
/// приложением, а не с сервером, и лечится это по-разному.
#[derive(Debug, Error)]
pub enum InboundError {
    /// Приложение говорит не на том протоколе.
    #[error("не SOCKS5: первый байт {0:#04x}, ожидался 0x05")]
    NotSocks5(u8),

    /// Клиент не предложил ни одного поддерживаемого способа проверки.
    #[error("клиент не предложил подходящего способа аутентификации")]
    NoAcceptableAuth,

    /// Неверный логин или пароль.
    #[error("неверный логин или пароль")]
    AuthFailed,

    /// Команда, которой у нас нет.
    #[error("команда SOCKS5 {0:#04x} не поддерживается")]
    UnsupportedCommand(u8),

    /// Неизвестный вид адреса.
    #[error("вид адреса {0:#04x} не поддерживается")]
    UnsupportedAddressType(u8),

    /// Адрес не разбирается.
    #[error("адрес не разбирается: {0}")]
    BadAddress(String),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl InboundError {
    /// Код ответа SOCKS5 для этой ошибки.
    ///
    /// Приложение показывает пользователю именно его, поэтому «отказано в
    /// соединении» и «сеть недоступна» должны различаться: браузер по ним
    /// пишет разные сообщения, и на них смотрят при разборе неполадок.
    pub fn socks5_reply(&self) -> u8 {
        match self {
            Self::UnsupportedCommand(_) => 0x07,
            Self::UnsupportedAddressType(_) => 0x08,
            Self::Io(err) => match err.kind() {
                std::io::ErrorKind::ConnectionRefused => 0x05,
                std::io::ErrorKind::HostUnreachable => 0x04,
                std::io::ErrorKind::NetworkUnreachable => 0x03,
                _ => 0x01,
            },
            _ => 0x01,
        }
    }
}
