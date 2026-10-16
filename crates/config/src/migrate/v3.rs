//! Миграция на схему версии 3: режим стал действием для «всего остального».
//!
//! Прежние имена режима переводит разбор ([`TunnelMode`]); здесь только номер:
//! прежняя сборка не поймёт `tunnel` и должна отказаться по версии, а не по разбору.
//!
//! [`TunnelMode`]: crate::schema::routing::TunnelMode

use crate::schema::RootConfig;

/// Поднимает файл версии 2 до версии 3.
pub fn from_v2(mut config: RootConfig) -> RootConfig {
    config.version = 3;
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::routing::TunnelMode;

    #[test]
    fn an_allowlist_file_still_sends_the_rest_direct() {
        let raw = "version = 2\n[routing]\nmode = \"allowlist\"\n";
        let config: RootConfig = toml::from_str(raw).expect("разбирается");

        let migrated = from_v2(config);
        assert_eq!(migrated.routing.mode, TunnelMode::Direct);
        assert_eq!(migrated.version, 3);
    }
}
