//! Владелец соединения по локальному порту, без драйвера ядра.
//!
//! Windows: `GetExtended{Tcp,Udp}Table`; Linux: `/proc/net` + `/proc/*/fd`;
//! macOS: `proc_pidfdinfo`. Короткое соединение может остаться без владельца —
//! оно не блокируется, а идёт по умолчанию режима.

pub mod cache;
pub mod enumerate;
pub mod icon;
pub mod identity;
pub mod platform;
pub mod resolver;

pub use cache::IdentityCache;
pub use enumerate::{ProcessEnumerator, RunningApp, system_enumerator};
pub use identity::{ProcessIdentity, normalize_path};
pub use resolver::{FlowOwnerResolver, NoResolver, system_resolver};
