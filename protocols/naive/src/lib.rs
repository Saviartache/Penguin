//! NaiveProxy: `CONNECT` поверх HTTP/2 и HTTP/3, с дополнением трафика.
//!
//! `CONNECT` по HTTP/2 или HTTP/3 (снаружи неотличим от браузера) плюс
//! [`padding`] первых кадров. Схема снята с `klzgrad/naiveproxy`, тег
//! `v150.0.7871.63-1`, `src/net/tools/naive/` (детали в [`padding`]).
//!
//! ```text
//!  factory ──┬─► outbound/h2 ──► transport/h2 (TCP + TLS + h2)
//!            └─► outbound/h3 ──► transport/h3 (QUIC + HTTP/3)
//! ```
//!
//! `udp = false` (`CONNECT` без датаграмм), `multiplex = true`. Не
//! реализованы: отпечаток Chrome у HTTP/3, `fastopen`, обрамление
//! `RST_STREAM` (`spdy_session.cc`), HPACK-значение `padding`. Сокеты выдаёт
//! [`penguin_proto::dialer::Dialer`].

pub mod basic;
pub mod config;
pub mod connect;
pub mod error;
pub mod factory;
pub mod outbound;
pub mod padding;
pub mod transport;

pub use config::NaiveConfig;
pub use error::{NaiveError, NaiveResult};
pub use factory::NaiveFactory;
pub use outbound::{NaiveHttp2Outbound, NaiveHttp3Outbound};

/// Имя протокола в конфигурации: `CONNECT` поверх HTTP/2 (менять нельзя).
pub const PROTOCOL_HTTP2: &str = "http2";

/// Имя протокола в конфигурации: `CONNECT` поверх HTTP/3 (менять нельзя).
pub const PROTOCOL_HTTP3: &str = "http3";
