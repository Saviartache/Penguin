//! Соединение с сервером: HTTP/2 поверх TCP+TLS, HTTP/3 поверх QUIC.
//!
//! Сокет выдаёт [`penguin_proto::dialer::Dialer`] (`AGENTS.md`, §3).

pub mod h2;
pub mod h3;
