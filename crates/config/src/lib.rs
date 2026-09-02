//! Схема конфигурации, чтение, запись, миграции.
//!
//! Крейт ничего не знает о протоколах: параметры направления лежат в
//! [`schema::outbound::RawOutbound`] непрозрачным JSON и разбираются только
//! самим протоколом. Иначе каждый новый протокол правил бы общий файл, который
//! читают все.

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
