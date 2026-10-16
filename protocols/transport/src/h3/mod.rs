//! HTTP/3 клиента (RFC 9114) поверх `quinn`. Своя реализация: `h3` 0.0.8 шлёт
//! `:scheme`/`:path` в `CONNECT` (против §4.4) и не отдаёт номер потока для
//! датаграмм. Есть запросы, расширенный `CONNECT` (9220), датаграммы (9297),
//! `GOAWAY`; нет динамической таблицы QPACK и проталкивания.
//!
//! Константы сняты с RFC 9114/9204/9220/9297/7541; векторы — RFC 7541 и 9204 прил. B.
//! Против живого сервера не проверялось (`scripts/interop`).

pub mod code;
pub mod datagram;
pub mod error;
pub mod frame;
pub mod message;
pub mod qpack;
pub mod settings;

#[cfg(feature = "quic")]
mod connection;
#[cfg(feature = "quic")]
mod control;
#[cfg(feature = "quic")]
mod dispatch;
#[cfg(feature = "quic")]
mod reader;
#[cfg(feature = "quic")]
mod stream;

#[cfg(feature = "quic")]
pub use connection::{Connection, Options};
#[cfg(feature = "quic")]
pub use dispatch::DatagramReceiver;
pub use error::{H3Error, H3Result};
pub use message::{Request, Response};
#[cfg(feature = "quic")]
pub use stream::{RecvStream, RequestStream, SendStream};
