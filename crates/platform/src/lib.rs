//! Маршруты, брандмауэр, DNS и служба ОС.
//!
//! Всё, что здесь меняется в системе, надо уметь отменить, в том числе по аварийному пути;
//! неудавшаяся отмена — громкая [`error::PlatformError::RollbackFailed`].

#[cfg(windows)]
pub mod appearance;
pub mod autostart;
pub mod bind;
pub mod build;
#[cfg(windows)]
mod com;
// Внутренний модуль: системные программы там, где нативного интерфейса нет.
#[cfg(unix)]
mod command;
pub mod dialog;
pub mod dns_settings;
pub mod elevate;
pub mod error;
pub mod firewall;
pub mod instance;
pub mod interface;
pub mod leftovers;
pub mod privilege;
pub mod route;
pub mod service;
pub mod sockets;

pub use build::stamp as build_stamp;
pub use dns_settings::DnsOverride as DnsOverrideHandle;
pub use elevate::run_elevated;
pub use error::{PlatformError, PlatformResult};
pub use firewall::{FirewallRules, KillSwitch};
pub use interface::{DefaultRoute, default_route};
pub use privilege::{Privilege, is_elevated};
pub use route::{Route, RouteGuard};
pub use service::ServiceStatus;
