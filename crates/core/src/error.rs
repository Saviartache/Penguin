//! Классификация ошибок, общая для всех слоёв: что показать пользователю и стоит ли повторять.

use thiserror::Error;

/// Результат операции над доменными типами.
pub type CoreResult<T> = Result<T, CoreError>;

/// Ошибка разбора или проверки доменного типа.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoreError {
    /// Строка не разбирается как адрес.
    #[error("не разбирается как адрес: {0}")]
    InvalidAddress(String),

    /// Порт вне допустимого диапазона или список портов пуст.
    #[error("неверный порт или диапазон портов: {0}")]
    InvalidPort(String),

    /// Строка не разбирается в ожидаемом виде. Сама строка не попадает в сообщение (§5.2).
    #[error("неверная запись {format}: {reason}")]
    InvalidEncoding {
        /// Вид записи: `base64`, `UUID`.
        format: &'static str,
        /// Что именно не так.
        reason: String,
    },

    /// Значение вне допустимых пределов.
    #[error("{field}: ожидалось {expected}, получено {got}")]
    OutOfRange {
        /// Имя поля.
        field: &'static str,
        /// Что ожидалось.
        expected: &'static str,
        /// Что пришло.
        got: String,
    },
}
