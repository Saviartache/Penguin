//! Служба, которая держит тоннель: права нужны ей, а не окну (иначе `iced`, `wgpu` и драйвер
//! видеокарты получили бы права администратора).
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

#[cfg(any(target_os = "macos", test))]
mod launchd;
// Копия программы, которую запускает диспетчер (общая забота launchd и systemd).
#[cfg(unix)]
mod stage;
#[cfg(any(target_os = "linux", test))]
mod systemd;

use std::path::Path;

use crate::error::PlatformResult;

/// Имя службы в системе; стоит у установленных служб — менять нельзя.
pub const SERVICE_NAME: &str = "PenguinVpn";

/// Имя, которое видит человек в списке служб.
pub const SERVICE_DISPLAY_NAME: &str = "Penguin VPN";

/// В каком состоянии служба.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    /// Не установлена (не ошибка: клиент работает и в режиме прокси).
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

/// Ставит службу или переставляет на указанный файл; прежнюю заранее не снимает, чтобы при
/// неудаче не остаться без службы с поднятым тоннелем.
pub fn install(executable: &Path) -> PlatformResult<()> {
    #[cfg(windows)]
    {
        windows::install(executable)
    }
    #[cfg(target_os = "linux")]
    {
        linux::install(executable)
    }
    #[cfg(target_os = "macos")]
    {
        macos::install(executable)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
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
    #[cfg(target_os = "linux")]
    {
        linux::uninstall()
    }
    #[cfg(target_os = "macos")]
    {
        macos::uninstall()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
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
    #[cfg(target_os = "linux")]
    {
        linux::start()
    }
    #[cfg(target_os = "macos")]
    {
        macos::start()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
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
    #[cfg(target_os = "linux")]
    {
        linux::stop()
    }
    #[cfg(target_os = "macos")]
    {
        macos::stop()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
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
    #[cfg(target_os = "linux")]
    {
        linux::status()
    }
    #[cfg(target_os = "macos")]
    {
        macos::status()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Ok(ServiceStatus::NotInstalled)
    }
}

/// Зарегистрирована ли служба на тот самый файл, который сейчас работает.
///
/// `false` и когда службы нет, и когда выяснить не удалось: дорога одна — переустановить. На
/// macOS и Linux сравниваются не пути, а сборки (`runs_current_build`): диспетчер запускает копию.
pub fn matches_current_executable() -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::runs_current_build()
    }
    #[cfg(target_os = "linux")]
    {
        linux::runs_current_build()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let (Ok(registered), Ok(current)) = (registered_executable(), std::env::current_exe())
        else {
            return false;
        };
        let Some(registered) = registered else {
            return false;
        };

        same_file(&registered, &current)
    }
}

/// Записан ли в описании службы ровно тот файл, который сейчас работает.
///
/// Строже [`matches_current_executable`]: служба, поставленная по ссылке на программу
/// (`scripts/package.sh`), указывает на файл, которого после пересборки может не быть, а
/// диспетчер читает описание буквально. На macOS и Linux — тот же вопрос про сборку.
pub fn registered_verbatim() -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::runs_current_build()
    }
    #[cfg(target_os = "linux")]
    {
        linux::runs_current_build()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let (Ok(Some(registered)), Ok(current)) =
            (registered_executable(), std::env::current_exe())
        else {
            return false;
        };
        current
            .canonicalize()
            .is_ok_and(|current| registered == current)
    }
}

/// Путь к файлу, который зарегистрирован службой; `None` — службы нет.
pub fn registered_executable() -> PlatformResult<Option<std::path::PathBuf>> {
    #[cfg(windows)]
    {
        windows::registered_executable()
    }
    #[cfg(target_os = "linux")]
    {
        linux::registered_executable()
    }
    #[cfg(target_os = "macos")]
    {
        macos::registered_executable()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Ok(None)
    }
}

/// Один ли это файл (`canonicalize`: пути пишут по-разному); отсутствующий файл не совпадает.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn same_file(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn a_missing_file_never_matches() {
        assert!(!same_file(
            Path::new("Z:/нет/такого/penguin.exe"),
            Path::new("Z:/нет/такого/penguin.exe")
        ));
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn the_same_file_written_differently_still_matches() {
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
        let _ = status();
    }
}
