//! Миграции конфигурации между версиями схемы.
//!
//! Миграция вперёд бывает, миграции назад не бывает. Файл из будущего не
//! переписывается умолчаниями, а отвергается с внятным сообщением: молча
//! потерять настройки, которых эта сборка не знает, хуже, чем отказаться
//! работать.

pub mod v1;
pub mod v2;

use crate::error::{ConfigError, ConfigResult};
use crate::schema::{RootConfig, SCHEMA_VERSION};

/// Приводит настройки к текущей версии схемы.
pub fn migrate(mut config: RootConfig) -> ConfigResult<RootConfig> {
    if config.version > SCHEMA_VERSION {
        return Err(ConfigError::FutureVersion {
            found: config.version,
            supported: SCHEMA_VERSION,
        });
    }

    // Каждый шаг поднимает версию ровно на единицу и отвечает только за свой
    // переход. Цепочка из таких шагов переносит файл любой давности, и ни
    // один шаг не приходится переписывать при появлении следующего.
    while config.version < SCHEMA_VERSION {
        config = match config.version {
            0 => v1::from_v0(config),
            1 => v2::from_v1(config),
            other => {
                return Err(ConfigError::invalid(
                    "version",
                    format!("нет миграции с версии {other}"),
                ));
            }
        };
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brings_v0_up_to_date() {
        let config = RootConfig {
            version: 0,
            ..RootConfig::default()
        };
        let migrated = migrate(config).expect("мигрирует");
        assert_eq!(migrated.version, SCHEMA_VERSION);
    }

    #[test]
    fn refuses_future_version() {
        let config = RootConfig {
            version: SCHEMA_VERSION + 1,
            ..RootConfig::default()
        };
        assert!(matches!(
            migrate(config),
            Err(ConfigError::FutureVersion { .. })
        ));
    }

    #[test]
    fn current_version_is_untouched() {
        let config = RootConfig::default();
        let migrated = migrate(config).expect("мигрирует");
        assert_eq!(migrated.version, SCHEMA_VERSION);
    }
}
