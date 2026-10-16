//! Миграция на схему версии 1.
//!
//! Версия 0 — файл без поля `version`; меняется только номер.

use crate::schema::RootConfig;

/// Поднимает файл версии 0 до версии 1.
pub fn from_v0(mut config: RootConfig) -> RootConfig {
    config.version = 1;
    config
}
