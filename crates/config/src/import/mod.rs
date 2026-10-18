//! Импорт чужого: списки правил в группы набора, `.conf` в профиль.

mod surge;
mod wireguard;

pub(crate) use surge::title;
pub use surge::{Imported, parse_surge};
pub use wireguard::parse_wireguard_conf;
