//! Ошибки обновления.

use std::path::PathBuf;

/// Результат операций крейта.
pub type UpdateResult<T> = Result<T, UpdateError>;

/// Почему обновить не вышло.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// Сеть, TLS или статус ответа.
    #[error("сеть: {0}")]
    Network(String),
    /// Адрес вне разрешённых узлов GitHub или не HTTPS.
    #[error("адрес не разрешён: {0}")]
    ForbiddenUrl(String),
    /// Ответ больше допустимого.
    #[error("ответ больше {limit} байт")]
    TooLarge {
        /// Предел.
        limit: u64,
    },
    /// Ответ API не разобрался.
    #[error("ответ GitHub не разобрался: {0}")]
    BadResponse(String),
    /// Номер версии не в формате `major.minor.patch`.
    #[error("версия `{0}` не в формате major.minor.patch")]
    BadVersion(String),
    /// В релизе нет поставки под эту систему.
    #[error("в релизе нет поставки `{0}`")]
    NoAsset(String),
    /// Эта система не собирается в релизах.
    #[error("для этой системы поставок нет")]
    UnsupportedTarget,
    /// В `SHA256SUMS` нет строки для архива.
    #[error("в SHA256SUMS нет суммы для `{0}`")]
    MissingChecksum(String),
    /// Сумма архива не сошлась: файл подменён или повреждён.
    #[error("SHA-256 не сошёлся: ждали {expected}, получили {actual}")]
    ChecksumMismatch {
        /// Из `SHA256SUMS`.
        expected: String,
        /// Посчитанная.
        actual: String,
    },
    /// Путь внутри архива выходит за его пределы.
    #[error("небезопасный путь в архиве: {0}")]
    UnsafePath(String),
    /// Архив повреждён или не тот формат.
    #[error("архив: {0}")]
    Archive(String),
    /// В архиве нет нужного файла.
    #[error("в архиве нет `{0}`")]
    MemberMissing(String),
    /// Нет права записи рядом с исполняемым файлом.
    #[error("нет права записи в {}", .0.display())]
    NotWritable(PathBuf),
    /// Файловая операция.
    #[error("{}: {source}", path.display())]
    Io {
        /// Файл.
        path: PathBuf,
        /// Причина.
        source: std::io::Error,
    },
}

impl UpdateError {
    /// Ошибка файловой операции с путём.
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
