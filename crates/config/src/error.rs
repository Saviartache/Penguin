//! Ошибки конфигурации с указанием места в файле.

use std::path::PathBuf;

use thiserror::Error;

/// Результат работы с конфигурацией.
pub type ConfigResult<T> = Result<T, ConfigError>;

/// Что пошло не так с файлом настроек.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Файл не читается или не пишется.
    #[error("файл {path}: {source}")]
    Io {
        /// Путь к файлу.
        path: PathBuf,
        /// Исходная ошибка.
        #[source]
        source: std::io::Error,
    },

    /// Файл не разбирается.
    ///
    /// Сообщение от `toml` содержит строку и столбец — их и показываем, иначе
    /// пользователю остаётся искать опечатку в файле на двести строк глазами.
    #[error("{path}: {message}")]
    Parse {
        /// Путь к файлу.
        path: PathBuf,
        /// Что именно не разобралось, со строкой и столбцом.
        message: String,
    },

    /// Файл разобрался, но настройки противоречивы.
    #[error("{field}: {message}")]
    Invalid {
        /// Поле, к которому относится претензия.
        field: String,
        /// В чём претензия.
        message: String,
    },

    /// Версия схемы новее той, что понимает эта сборка.
    ///
    /// Отдельный случай, потому что действие другое: не «почини файл», а
    /// «обнови клиент». Молча переписать такой файл нельзя — потеряются
    /// настройки, которых эта версия не знает.
    #[error(
        "файл настроек создан более новой версией клиента (схема {found}, поддерживается {supported})"
    )]
    FutureVersion {
        /// Версия в файле.
        found: u32,
        /// Версия, которую понимает эта сборка.
        supported: u32,
    },

    /// Не удалось определить каталог настроек.
    #[error("не удалось определить каталог настроек пользователя")]
    NoConfigDir,

    /// Файл занят другим экземпляром клиента.
    #[error("файл настроек занят другим экземпляром клиента")]
    Locked,
}

impl ConfigError {
    /// Ошибка ввода-вывода с путём.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// Ошибка проверки.
    pub fn invalid(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Invalid {
            field: field.into(),
            message: message.into(),
        }
    }
}
