//! Ошибки разрешения имён.

use thiserror::Error;

/// Результат работы с DNS.
pub type DnsResult<T> = Result<T, DnsError>;

/// Что пошло не так при разрешении имени.
#[derive(Debug, Error)]
pub enum DnsError {
    /// Апстрим не ответил или ответил отказом.
    #[error("апстрим DNS: {0}")]
    Upstream(String),

    /// Ответ не разбирается.
    #[error("ответ DNS не разбирается: {0}")]
    Malformed(String),

    /// Такого имени нет (NXDOMAIN).
    ///
    /// Отдельно от [`Self::Upstream`]: «имени нет» — это законный ответ,
    /// который надо запомнить в кэше, а «спросить не удалось» — повод
    /// попробовать другой апстрим.
    #[error("имя не существует: {0}")]
    NotFound(String),

    /// Пул подставных адресов исчерпан.
    #[error("закончились подставные адреса; расширьте dns.fake_ip_range")]
    FakeIpExhausted,

    /// Настройки DNS неверны.
    #[error("настройки DNS: {0}")]
    Config(String),

    /// Ошибка ввода-вывода.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
