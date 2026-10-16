//! UDP поверх TUN: разбор и сборка вручную, мимо smoltcp (состояния у UDP нет).

pub mod session;
pub mod table;

pub use session::{SESSION_TIMEOUT, Session, SessionKey, build_datagram};
pub use table::SessionTable;
