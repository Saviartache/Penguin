//! Автозапуск интерфейса при входе (не службы): запись в настройках текущего пользователя —
//! ветка реестра, `~/.config/autostart` или `~/Library/LaunchAgents`; права администратора не нужны.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

use crate::error::PlatformResult;

/// Имя записи автозапуска.
#[cfg(windows)]
const ENTRY_NAME: &str = "Penguin";

/// Аргументы запуска: свёрнутым в лоток, чтобы окно не вставало поверх рабочего стола.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
const ARGUMENTS: &[&str] = &["--tray"];

/// Включает автозапуск.
pub fn enable(executable: &std::path::Path) -> PlatformResult<()> {
    set_enabled(Some(executable))
}

/// Выключает автозапуск.
pub fn disable() -> PlatformResult<()> {
    set_enabled(None)
}

/// Включён ли автозапуск.
pub fn is_enabled() -> bool {
    #[cfg(windows)]
    {
        windows::read().is_some()
    }
    #[cfg(target_os = "linux")]
    {
        linux::exists()
    }
    #[cfg(target_os = "macos")]
    {
        macos::exists()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

fn set_enabled(executable: Option<&std::path::Path>) -> PlatformResult<()> {
    #[cfg(windows)]
    {
        match executable {
            Some(path) => windows::write(path),
            None => windows::remove(),
        }
    }
    #[cfg(target_os = "linux")]
    {
        match executable {
            Some(path) => linux::write(path),
            None => linux::remove(),
        }
    }
    #[cfg(target_os = "macos")]
    {
        match executable {
            Some(path) => macos::write(path),
            None => macos::remove(),
        }
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = executable;
        Err(crate::error::PlatformError::Unsupported("автозапуск"))
    }
}

/// Домашний каталог из окружения: под `sudo` база учётных записей назвала бы каталог root.
#[cfg(unix)]
fn home() -> PlatformResult<std::path::PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(std::path::PathBuf::from)
        .ok_or_else(|| {
            crate::error::PlatformError::Service("система не назвала домашний каталог".to_owned())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asking_never_panics() {
        let _ = is_enabled();
    }

    #[cfg(unix)]
    #[test]
    fn the_home_directory_is_known() {
        assert!(home().is_ok());
    }
}
