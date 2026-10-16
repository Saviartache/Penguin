//! Схема конфигурации, чтение, запись, миграции.
//!
//! Параметры протоколов лежат в [`schema::outbound::RawOutbound`] непрозрачным JSON.

pub mod error;
pub mod logs;
pub mod migrate;
pub mod paths;
pub mod schema;
pub mod store;
pub mod validate;

pub use error::{ConfigError, ConfigResult};
pub use paths::Paths;
pub use schema::{RootConfig, SCHEMA_VERSION};
pub use store::ConfigStore;
