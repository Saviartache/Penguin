//! Всё, что требует прав и знания операционной системы: маршруты, брандмауэр,
//! служба.
//!
//! Крейт делает с системой то, чего обычная программа делать не может, и у
//! всего, что он делает, есть общее свойство: **это надо уметь отменить**.
//!
//! Маршрут, оставшийся от упавшего клиента, ведёт в несуществующий адаптер —
//! сеть не работает вовсе. Правило брандмауэра, оставшееся от kill switch, —
//! то же самое. Подменённые настройки DNS — то же самое. Поэтому здесь всюду
//! одна и та же схема: изменение записывается, отмена идёт даже по аварийному
//! пути, а неудавшаяся отмена — отдельная громкая ошибка
//! ([`error::PlatformError::RollbackFailed`]).

pub mod autostart;
// Привязка сокета к интерфейсу: то, чем клиент защищает от тоннеля своё же
// соединение с сервером.
pub mod bind;
pub mod build;
// Часть работы делается системными программами — там, где своего интерфейса у
// системы нет. Модуль внутренний: наружу видны только действия, а не то,
// какой командой они сделаны.
#[cfg(unix)]
mod command;
pub mod dns_settings;
pub mod elevate;
pub mod error;
pub mod firewall;
pub mod interface;
pub mod privilege;
pub mod route;
pub mod service;

pub use build::stamp as build_stamp;
pub use dns_settings::DnsOverride as DnsOverrideHandle;
pub use elevate::run_elevated;
pub use error::{PlatformError, PlatformResult};
pub use firewall::{FirewallRules, KillSwitch};
pub use interface::{DefaultRoute, default_route};
pub use privilege::{Privilege, is_elevated};
pub use route::{Route, RouteGuard};
pub use service::ServiceStatus;
