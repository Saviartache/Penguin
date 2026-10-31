//! Pingwin по TCP: TLS 1.3 с ALPN `h2`, HTTP/2 — для тех, у кого режут UDP.
//!
//! ```text
//!  connection  одно соединение: TLS, опознание, запросы, пинг
//!  relay       CONNECT и канал датаграмм (капсулы)
//!  http1       прикрытие для тех, кто пришёл без `h2`
//! ```

pub(crate) mod connection;
mod http1;
mod relay;
