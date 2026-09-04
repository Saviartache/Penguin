//! Автозапуск клиента при входе в систему.
//!
//! Именно **интерфейса**, а не службы: служба ставится отдельно и стартует
//! сама вместе с системой. Здесь речь про окно, которое пользователь хочет
//! видеть после входа.
//!
//! Запись идёт туда, где живут настройки **текущего пользователя**, а не
//! машины: автозапуск — это выбор человека, а не настройка компьютера, и прав
//! администратора он требовать не должен. Отсюда и три разных места: ветка
//! реестра пользователя, `~/.config/autostart` и `~/Library/LaunchAgents`.

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

/// Домашний каталог пользователя.
///
/// Спрашивается у окружения, а не у базы учётных записей: под `sudo` вторая
/// назвала бы каталог суперпользователя, и запись легла бы не тому, кто
/// нажимал переключатель.
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
        // Вызывается при каждом открытии настроек.
        let _ = is_enabled();
    }

    #[cfg(unix)]
    #[test]
    fn the_home_directory_is_known() {
        // Без него автозапуск не включить, и сказать об этом надо внятно, а
        // не паникой.
        assert!(home().is_ok());
    }
}
