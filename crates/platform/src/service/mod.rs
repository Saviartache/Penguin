//! Установка и управление службой, которая держит тоннель.
//!
//! Разделение на службу и окно — не удобство, а требование безопасности.
//! TUN-адаптер, маршруты и брандмауэр требуют прав администратора; запускать
//! с ними интерфейс значило бы дать те же права `iced`, `wgpu` и драйверу
//! видеокарты. Служба работает под системной учётной записью и не имеет ни
//! окна, ни графики; интерфейс работает под пользователем и только просит.
//!
//! ```text
//!   penguin-gui (пользователь) ──канал управления──► penguin-daemon (система)
//! ```

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

use std::path::Path;

use crate::error::PlatformResult;

/// Имя службы в системе.
///
/// Стоит у уже установленных служб — менять нельзя.
pub const SERVICE_NAME: &str = "PenguinVpn";

/// Имя, которое видит человек в списке служб.
pub const SERVICE_DISPLAY_NAME: &str = "Penguin VPN";

/// В каком состоянии служба.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    /// Не установлена. Не ошибка: клиент умеет работать и в режиме прокси.
    NotInstalled,
    /// Установлена, но не запущена.
    Stopped,
    /// Работает.
    Running,
    /// Запускается или останавливается.
    Transitioning,
}

impl ServiceStatus {
    /// Служба готова принимать команды.
    pub fn is_running(self) -> bool {
        self == Self::Running
    }

    /// Как это назвать в интерфейсе.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotInstalled => "не установлена",
            Self::Stopped => "остановлена",
            Self::Running => "работает",
            Self::Transitioning => "переключается",
        }
    }
}

/// Ставит службу.
pub fn install(executable: &Path) -> PlatformResult<()> {
    #[cfg(windows)]
    {
        windows::install(executable)
    }
    #[cfg(not(windows))]
    {
        let _ = executable;
        Err(crate::error::PlatformError::Unsupported("установка службы"))
    }
}

/// Убирает службу.
pub fn uninstall() -> PlatformResult<()> {
    #[cfg(windows)]
    {
        windows::uninstall()
    }
    #[cfg(not(windows))]
    {
        Err(crate::error::PlatformError::Unsupported("удаление службы"))
    }
}

/// Запускает службу.
pub fn start() -> PlatformResult<()> {
    #[cfg(windows)]
    {
        windows::start()
    }
    #[cfg(not(windows))]
    {
        Err(crate::error::PlatformError::Unsupported("запуск службы"))
    }
}

/// Останавливает службу.
pub fn stop() -> PlatformResult<()> {
    #[cfg(windows)]
    {
        windows::stop()
    }
    #[cfg(not(windows))]
    {
        Err(crate::error::PlatformError::Unsupported("остановка службы"))
    }
}

/// Состояние службы.
pub fn status() -> PlatformResult<ServiceStatus> {
    #[cfg(windows)]
    {
        windows::status()
    }
    #[cfg(not(windows))]
    {
        Ok(ServiceStatus::NotInstalled)
    }
}

/// Зарегистрирована ли служба на тот самый файл, который сейчас работает.
///
/// Разные пути означают, что тоннель поднимает **не та** программа, которую
/// запустил человек: другая сборка, другой каталог. Рядом с ней может не быть
/// ни драйвера, ни нужных настроек, а код в ней — прошлогодний. Снаружи это
/// выглядит как «поставил новую версию, а ошибки те же».
///
/// `false` и когда службы нет, и когда состояние выяснить не удалось: в обоих
/// случаях дальше идти той же дорогой — переустановить.
pub fn matches_current_executable() -> bool {
    let (Ok(registered), Ok(current)) = (registered_executable(), std::env::current_exe()) else {
        return false;
    };
    let Some(registered) = registered else {
        return false;
    };

    same_file(&registered, &current)
}

/// Путь к файлу, который зарегистрирован службой. `None` — службы нет.
pub fn registered_executable() -> PlatformResult<Option<std::path::PathBuf>> {
    #[cfg(windows)]
    {
        windows::registered_executable()
    }
    #[cfg(not(windows))]
    {
        Ok(None)
    }
}

/// Один ли это файл.
///
/// Сравнение строк не годится: один и тот же файл записывают и через прямые
/// слэши, и через обратные, и с другим регистром буквы диска.
fn same_file(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        // Зарегистрированного файла может уже не быть на месте — это и есть
        // тот случай, ради которого проверка затевалась.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_never_matches() {
        // Служба, указывающая на удалённую сборку, — обычное дело после
        // обновления, и считать её своей нельзя.
        assert!(!same_file(
            Path::new("Z:/нет/такого/penguin.exe"),
            Path::new("Z:/нет/такого/penguin.exe")
        ));
    }

    #[test]
    fn the_same_file_written_differently_still_matches() {
        // Один и тот же файл записывают по-разному; сравнение строк на этом
        // ломается, а `canonicalize` — нет.
        let current = std::env::current_exe().expect("свой путь известен");
        let parent = current.parent().expect("каталог есть");
        let name = current.file_name().expect("имя есть");

        let roundabout = parent.join(".").join(name);
        assert!(same_file(&current, &roundabout), "{roundabout:?}");
    }

    #[test]
    fn only_running_accepts_commands() {
        assert!(ServiceStatus::Running.is_running());
        for status in [
            ServiceStatus::NotInstalled,
            ServiceStatus::Stopped,
            ServiceStatus::Transitioning,
        ] {
            assert!(!status.is_running());
        }
    }

    #[test]
    fn every_status_has_a_human_name() {
        for status in [
            ServiceStatus::NotInstalled,
            ServiceStatus::Stopped,
            ServiceStatus::Running,
            ServiceStatus::Transitioning,
        ] {
            assert!(!status.as_str().is_empty());
        }
    }

    #[test]
    fn querying_status_never_panics() {
        // Вызывается при каждом запуске интерфейса.
        let _ = status();
    }
}
