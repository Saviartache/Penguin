//! Перенос XHTTP (бывший SplitHTTP) Xray: по HTTP/3 поверх TLS, по HTTP/2 поверх Reality.
//!
//! Только `stream-one`: один `POST`, тела запроса и ответа несут данные (Xray `hub.go`:
//! режимы `auto`, `stream-one`, `stream-up`; `packet-up` даст `400`). Отступ — умолчание
//! Xray, свой `xPaddingBytes`/`xPaddingObfsMode` сервер не примет.

#[cfg(feature = "quic")]
mod client;
#[cfg(feature = "h2")]
pub mod h2;
mod request;
#[cfg(feature = "quic")]
mod stream;

#[cfg(feature = "quic")]
pub use client::{XhttpClient, XhttpTarget};
pub use request::stream_one;
#[cfg(feature = "quic")]
pub use stream::XhttpStream;
