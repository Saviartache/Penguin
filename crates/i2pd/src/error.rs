//! Ошибки i2pd.

use std::path::{Path, PathBuf};

/// Результат операций крейта.
pub type I2pdResult<T> = Result<T, I2pdError>;

/// Почему i2pd не поставлен или не запущен.
#[derive(Debug, thiserror::Error)]
pub enum I2pdError {
    /// Для этой системы выпуск не закреплён.
    #[error("i2pd для этой системы не собирается")]
    UnsupportedTarget,
    /// Файла нет: его ставит `penguin i2pd install`.
    #[error("i2pd не установлен: нажмите «Установить i2pd» или выполните `penguin i2pd install`")]
    NotInstalled,
    /// Сумма не сошлась: файл подменён, повреждён или от другой версии.
    #[error("SHA-256 i2pd не сошёлся: ждали {expected}, получили {actual}; переустановите i2pd")]
    ChecksumMismatch {
        /// Закреплённая.
        expected: &'static str,
        /// Посчитанная.
        actual: String,
    },
    /// Процесс вышел, не открыв HTTP-прокси.
    #[error("i2pd завершился при запуске ({0}); журнал — {1}")]
    Exited(String, PathBuf),
    /// HTTP-прокси не открылся в срок: обычно не скачался список узлов (reseed).
    #[error(
        "i2pd не открыл HTTP-прокси за {0} с — вероятно, серверы начальных узлов I2P (reseed) недоступны; журнал — {1}"
    )]
    NotReady(u64, PathBuf),
    /// Нет пользователя без прав: от root i2pd не запускается.
    #[error("нет пользователя `{0}`: от root i2pd не запускается")]
    NoAccount(&'static str),
    /// Не поднялся обход TUN.
    #[error("обход тоннеля для i2pd: {0}")]
    Bypass(String),
    /// Файловая операция.
    #[error("{}: {source}", path.display())]
    Io {
        /// Файл.
        path: PathBuf,
        /// Причина.
        source: std::io::Error,
    },
}

impl I2pdError {
    /// Ошибка файловой операции с путём.
    pub(crate) fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}
