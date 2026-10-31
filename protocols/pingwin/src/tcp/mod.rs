//! Pingwin по TCP: TLS 1.3 с ALPN `h2`, HTTP/2 — там, где режут UDP и с ним QUIC.
//!
//! ```text
//!  pool      три соединения: два под потоки, одно под датаграммы
//!  session   TCP, TLS, HTTP/2, опознание, пинг
//!  io        половины потока HTTP/2 (общие с сервером)
//!  datagram  канал `connect-udp`, датаграммы капсулами (`wire::capsule`)
//! ```

pub mod datagram;
pub mod io;
pub(crate) mod pool;
pub(crate) mod session;
