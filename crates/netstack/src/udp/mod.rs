//! UDP поверх TUN.
//!
//! Разбирается и собирается вручную, минуя smoltcp: у UDP нет состояния, а
//! сокет в стеке на каждую пару адресов обошёлся бы дороже, чем разбор
//! восьмибайтового заголовка. Подробнее — в [`session`].

pub mod session;
pub mod table;

pub use session::{SESSION_TIMEOUT, Session, SessionKey, build_datagram};
pub use table::SessionTable;
