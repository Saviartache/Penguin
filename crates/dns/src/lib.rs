//! Разрешение имён и защита от утечек DNS.
//!
//! Две задачи: не дать именам утечь мимо тоннеля (перехват порта 53 из TUN,
//! [`hijack`]) и сохранить имя для правил по доменам (подставные адреса,
//! [`fakeip`]). Разрешателей два: **основной** отвечает приложениям через
//! тоннель, **загрузочный** узнаёт адрес сервера мимо тоннеля.

pub mod bootstrap;
pub mod cache;
pub mod config;
pub mod error;
pub mod fakeip;
pub mod hijack;
pub mod hosts;
pub mod message;
pub mod resolver;
pub mod upstream;
mod wire;

pub use bootstrap::BootstrapResolver;
pub use cache::DnsCache;
pub use config::{DnsConfig, DnsMode};
pub use error::{DnsError, DnsResult};
pub use fakeip::{FakeIpMap, FakeIpPool};
pub use hijack::DnsHijacker;
pub use hosts::Hosts;
pub use resolver::{Resolver, SystemResolver};
pub use upstream::Upstream;
