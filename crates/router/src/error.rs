//! Ошибки сборки набора правил.
//!
//! Все они возникают при сборке, а не при разборе соединения: на горячем пути
//! ошибок нет вовсе, там есть только решение.

use thiserror::Error;

/// Результат сборки правил.
pub type RouterResult<T> = Result<T, RouterError>;

/// Что не так с правилами.
#[derive(Debug, Error)]
pub enum RouterError {
    /// Правило не собирается.
    ///
    /// Сообщение называет правило по идентификатору: в наборе из тридцати
    /// правил «не разбирается подсеть» без указания места бесполезно.
    #[error("правило `{id}`: {message}")]
    Rule {
        /// Идентификатор правила.
        id: String,
        /// Что именно не так.
        message: String,
    },

    /// Значение не разбирается.
    #[error("{0}")]
    Invalid(String),

    /// Условие этой сборкой не поддерживается.
    #[error("условие не поддерживается: {0}")]
    Unsupported(&'static str),

    /// Правило требует GeoIP, а база не загружена.
    #[error("правило требует базу GeoIP, но она не загружена")]
    MissingGeoIp,
}

impl RouterError {
    /// Ошибка с указанием правила.
    pub fn rule(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Rule {
            id: id.into(),
            message: message.into(),
        }
    }
}
