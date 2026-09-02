//! Настройки приложения: автозапуск, язык, тема, обновления.

use serde::{Deserialize, Serialize};

/// Поведение приложения, не влияющее на трафик.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppConfig {
    /// Запускать интерфейс при входе в систему.
    pub autostart: bool,
    /// Поднимать тоннель сразу при запуске.
    pub autoconnect: bool,
    /// Сворачивать в область уведомлений вместо закрытия.
    pub minimize_to_tray: bool,
    /// Язык интерфейса.
    pub language: Language,
    /// Тема оформления. Значение из кита (`uikit::ThemeType`) хранится
    /// строкой: конфигурация не должна зависеть от версии кита.
    pub theme: String,
    /// Подробность журнала.
    pub log_level: LogLevel,
    /// Проверять обновления.
    pub check_updates: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            autostart: false,
            autoconnect: false,
            minimize_to_tray: true,
            language: Language::Ru,
            theme: "dark".to_owned(),
            log_level: LogLevel::Info,
            check_updates: true,
        }
    }
}

/// Язык интерфейса.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    /// Русский.
    Ru,
    /// Английский.
    En,
}

/// Подробность журнала.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Только ошибки.
    Error,
    /// Ошибки и предупреждения.
    Warn,
    /// Ход работы.
    Info,
    /// Подробности: решения маршрутизатора по каждому соединению.
    Debug,
    /// Всё, включая содержимое кадров. Пароли при этом всё равно не пишутся.
    Trace,
}

impl LogLevel {
    /// Имя уровня в том виде, в каком его ждёт `tracing`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}
