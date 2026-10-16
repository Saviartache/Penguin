//! Входящие точки: откуда трафик попадает в клиент помимо TUN.
//!
//! [`socks5`] и [`http`] (`CONNECT`) работают без прав и драйвера, а приложение
//! отдаёт имя хоста, так что утечки DNS нет. Весь трафик машины ловит TUN
//! (`penguin-netstack`).

pub mod error;
pub mod http;
pub mod inbound;
mod relay;
pub mod socks5;

pub use error::{InboundError, InboundResult};
pub use http::HttpInbound;
pub use inbound::{Inbound, InboundHandler, InboundRequest};
pub use socks5::Socks5Inbound;
pub use socks5::auth::Credentials;
