//! Соединение с сервером: HTTP/2 поверх TCP+TLS или HTTP/3 поверх QUIC
//! (`PROTOCOL.md`, §3).
//!
//! Сокет выдаёт `Dialer` (`AGENTS.md`, §3).

pub mod h2;
pub mod h3;
pub mod link;

pub use link::Link;
