//! Разбор и сборка байт VLESS.
//!
//! Чистые функции над срезами, без сокетов и `tokio`.

pub mod addons;
pub mod request;
pub mod udp;
