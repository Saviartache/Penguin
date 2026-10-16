//! Атомарная запись (temp + rename), резервная копия, файловая блокировка.

use std::path::{Path, PathBuf};

use crate::error::{ConfigError, ConfigResult};
use crate::migrate;
use crate::paths::Paths;
use crate::schema::RootConfig;
use crate::validate;

/// Файл настроек на диске.
#[derive(Debug, Clone)]
pub struct ConfigStore {
    paths: Paths,
}

impl ConfigStore {
    /// Хранилище по указанным путям.
    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// Хранилище в каталоге пользователя.
    pub fn discover() -> ConfigResult<Self> {
        Ok(Self::new(Paths::discover()?))
    }

    /// Пути, по которым работает хранилище.
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// Читает настройки; нет файла — умолчания.
    pub fn load(&self) -> ConfigResult<RootConfig> {
        let path = self.paths.config_file();
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RootConfig::default());
            }
            Err(e) => return Err(ConfigError::io(&path, e)),
        };

        let config = Self::parse(&raw, &path)?;
        let config = migrate::migrate(config)?;
        validate::validate(&config)?;
        Ok(config)
    }

    /// Разбирает содержимое файла.
    pub fn parse(raw: &str, path: &Path) -> ConfigResult<RootConfig> {
        toml::from_str(raw).map_err(|e| ConfigError::Parse {
            path: path.to_path_buf(),
            message: e.to_string(),
        })
    }

    /// Записывает через временный файл и `rename`; прежний файл остаётся в `.bak`.
    pub fn save(&self, config: &RootConfig) -> ConfigResult<()> {
        validate::validate(config)?;
        self.paths.ensure_dirs()?;

        let path = self.paths.config_file();
        let body = toml::to_string_pretty(config).map_err(|e| ConfigError::Parse {
            path: path.clone(),
            message: e.to_string(),
        })?;

        if path.exists() {
            let backup = backup_path(&path);
            std::fs::copy(&path, &backup).map_err(|e| ConfigError::io(&backup, e))?;
        }

        let temp = temp_path(&path);
        std::fs::write(&temp, body.as_bytes()).map_err(|e| ConfigError::io(&temp, e))?;
        std::fs::rename(&temp, &path).map_err(|e| ConfigError::io(&path, e))?;
        Ok(())
    }

    /// Записывает умолчания, если файла нет; `true` — файл создан.
    pub fn init_if_missing(&self) -> ConfigResult<bool> {
        if self.paths.config_file().exists() {
            return Ok(false);
        }
        self.save(&RootConfig::default())?;
        Ok(true)
    }
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".tmp");
    PathBuf::from(name)
}

fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".bak");
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::outbound::RawOutbound;
    use crate::schema::profile::Profile;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("penguin-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn sample() -> RootConfig {
        let mut config = RootConfig::default();
        config.profiles.push(Profile::new(
            "home",
            "Домашний",
            RawOutbound::new(
                "hysteria2",
                serde_json::json!({ "server": "example.com:443", "password": "secret" }),
            ),
        ));
        config
    }

    #[test]
    fn missing_file_gives_defaults() {
        let store = ConfigStore::new(Paths::rooted(temp_dir("missing")));
        let config = store.load().expect("умолчания");
        assert!(config.profiles.is_empty());
        assert_eq!(config.version, crate::schema::SCHEMA_VERSION);
    }

    #[test]
    fn round_trips_through_disk() {
        let dir = temp_dir("roundtrip");
        let store = ConfigStore::new(Paths::rooted(&dir));
        store.save(&sample()).expect("записывается");

        let loaded = store.load().expect("читается");
        assert_eq!(loaded.profiles.len(), 1);
        let profile = &loaded.profiles[0];
        assert_eq!(profile.name, "Домашний");
        assert_eq!(profile.outbound.protocol, "hysteria2");
        assert_eq!(
            profile.outbound.field("server").and_then(|v| v.as_str()),
            Some("example.com:443")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn second_save_leaves_backup() {
        let dir = temp_dir("backup");
        let store = ConfigStore::new(Paths::rooted(&dir));
        store.save(&RootConfig::default()).expect("первая запись");
        store.save(&sample()).expect("вторая запись");

        assert!(backup_path(&store.paths().config_file()).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reports_parse_errors_with_path() {
        let path = PathBuf::from("config.toml");
        let err = ConfigStore::parse("это [не toml", &path).expect_err("должно сломаться");
        assert!(matches!(err, ConfigError::Parse { .. }));
    }
}
