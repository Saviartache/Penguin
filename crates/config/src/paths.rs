//! Где лежат конфиг, логи и данные на каждой ОС.
//!
//! Окно и служба работают от разных учётных записей, поэтому общий файл лежит
//! в [`Paths::machine`]; пока службы нет, хватает профиля пользователя.

use std::path::{Path, PathBuf};

use crate::error::{ConfigError, ConfigResult};

#[cfg(windows)]
const ORGANIZATION: &str = "Saviartache";
#[cfg(windows)]
const APPLICATION: &str = "Penguin";

/// Имя основного файла настроек.
pub const CONFIG_FILE: &str = "config.toml";

/// Набор путей клиента.
#[derive(Debug, Clone)]
pub struct Paths {
    config_dir: PathBuf,
    data_dir: PathBuf,
}

impl Paths {
    /// Пути, которые видят и окно, и служба.
    ///
    /// Общий каталог, если он существует; иначе профиль пользователя.
    pub fn discover() -> ConfigResult<Self> {
        if let Some(machine) = Self::machine()
            && machine.config_dir.is_dir()
        {
            return Ok(machine);
        }
        Self::user()
    }

    /// Пути в профиле текущего пользователя.
    ///
    /// `%APPDATA%` на Windows, `~/Library/Application Support` на macOS, XDG
    /// на Linux; `Err`, если нет `HOME` (или `APPDATA`).
    pub fn user() -> ConfigResult<Self> {
        #[cfg(windows)]
        {
            let root = PathBuf::from(std::env::var_os("APPDATA").ok_or(ConfigError::NoConfigDir)?)
                .join(ORGANIZATION)
                .join(APPLICATION);
            Ok(Self {
                config_dir: root.join("config"),
                data_dir: root.join("data"),
            })
        }
        #[cfg(target_os = "macos")]
        {
            let root = home()?.join("Library/Application Support/Saviartache.Penguin");
            Ok(Self {
                config_dir: root.clone(),
                data_dir: root,
            })
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            Ok(Self {
                config_dir: xdg_dir("XDG_CONFIG_HOME", ".config")?.join("penguin"),
                data_dir: xdg_dir("XDG_DATA_HOME", ".local/share")?.join("penguin"),
            })
        }
    }

    /// Общий каталог, одинаковый для всех учётных записей.
    ///
    /// `None`, если на Windows нет `ProgramData`. Писать может только служба.
    pub fn machine() -> Option<Self> {
        #[cfg(windows)]
        {
            let root = PathBuf::from(std::env::var_os("ProgramData")?)
                .join(ORGANIZATION)
                .join(APPLICATION);
            Some(Self {
                config_dir: root.join("config"),
                data_dir: root.join("data"),
            })
        }
        #[cfg(not(windows))]
        {
            Some(Self {
                config_dir: PathBuf::from("/etc/penguin"),
                data_dir: PathBuf::from("/var/lib/penguin"),
            })
        }
    }

    /// Пути внутри указанного каталога (переносимая сборка, тесты).
    pub fn rooted(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        Self {
            config_dir: root.to_path_buf(),
            data_dir: root.join("data"),
        }
    }

    /// Каталог настроек.
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// Каталог данных: журнал, база GeoIP, кэш подписок.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Основной файл настроек.
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join(CONFIG_FILE)
    }

    /// Файл журнала.
    pub fn log_file(&self) -> PathBuf {
        self.data_dir.join("penguin.log")
    }

    /// База GeoIP.
    pub fn geoip_file(&self) -> PathBuf {
        self.data_dir.join("geoip.mmdb")
    }

    /// Создаёт каталоги, если их нет.
    pub fn ensure_dirs(&self) -> ConfigResult<()> {
        for dir in [&self.config_dir, &self.data_dir] {
            std::fs::create_dir_all(dir).map_err(|e| ConfigError::io(dir, e))?;
        }
        Ok(())
    }
}

/// Домашний каталог текущего пользователя.
#[cfg(unix)]
fn home() -> ConfigResult<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .ok_or(ConfigError::NoConfigDir)
}

/// Каталог XDG: переменная с абсолютным путём, иначе умолчание в `HOME`.
#[cfg(all(unix, not(target_os = "macos")))]
fn xdg_dir(variable: &str, fallback: &str) -> ConfigResult<PathBuf> {
    match std::env::var_os(variable).map(PathBuf::from) {
        Some(path) if path.is_absolute() => Ok(path),
        _ => Ok(home()?.join(fallback)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_sets_are_different_places() {
        let user = Paths::user().expect("профиль пользователя известен");
        let machine = Paths::machine().expect("общий каталог известен");

        assert_ne!(user.config_dir(), machine.config_dir());
        assert_ne!(user.data_dir(), machine.data_dir());
    }

    #[test]
    fn discovery_picks_one_of_the_two() {
        let found = Paths::discover().expect("пути определяются");
        let user = Paths::user().expect("профиль пользователя известен");
        let machine = Paths::machine().expect("общий каталог известен");

        assert!(
            found.config_dir() == user.config_dir() || found.config_dir() == machine.config_dir(),
            "выбран каталог, которого нет ни в одном наборе: {}",
            found.config_dir().display()
        );
    }

    #[test]
    fn discovery_prefers_the_shared_directory_once_it_exists() {
        let machine = Paths::machine().expect("общий каталог известен");
        let found = Paths::discover().expect("пути определяются");

        if machine.config_dir().is_dir() {
            assert_eq!(found.config_dir(), machine.config_dir());
        } else {
            let user = Paths::user().expect("профиль пользователя известен");
            assert_eq!(found.config_dir(), user.config_dir());
        }
    }

    #[test]
    fn a_rooted_set_keeps_everything_together() {
        let paths = Paths::rooted("C:/penguin-portable");

        assert!(paths.config_file().starts_with("C:/penguin-portable"));
        assert!(paths.log_file().starts_with("C:/penguin-portable"));
        assert!(paths.geoip_file().starts_with("C:/penguin-portable"));
    }

    #[test]
    fn the_config_file_is_named_the_same_everywhere() {
        for paths in [
            Paths::user().expect("профиль"),
            Paths::machine().expect("общий"),
            Paths::rooted("C:/penguin-portable"),
        ] {
            assert_eq!(
                paths
                    .config_file()
                    .file_name()
                    .and_then(|name| name.to_str()),
                Some(CONFIG_FILE)
            );
        }
    }
}
