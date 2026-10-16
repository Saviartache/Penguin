//! Перенос XHTTP (бывший SplitHTTP) Xray по HTTP/3.
//!
//! Только `stream-one`: один `POST`, тела запроса и ответа несут данные (Xray `hub.go`:
//! режимы `auto`, `stream-one`, `stream-up`; `packet-up` даст `400`). Только HTTP/3;
//! отступ — умолчание Xray, свой `xPaddingBytes`/`xPaddingObfsMode` сервер не примет.

mod client;
mod request;
mod stream;

pub use client::{XhttpClient, XhttpTarget};
pub use request::stream_one;
pub use stream::XhttpStream;
