//! TCP Shadowsocks 2022: заголовок с меткой времени и своя AEAD-раскладка.
//!
//! ```text
//!  header  байтовая раскладка заголовков — без шифрования, без сети
//!  stream  сам поток: соль, заголовок, дальше — обычные куски данных
//! ```
//!
//! Устройство и раскладка байт сверены построчно с `shadowsocks-rust`
//! (`crates/shadowsocks/src/relay/tcprelay/aead_2022.rs`,
//! `proxy_stream/protocol/v2.rs`) и независимо с `sing-shadowsocks2`
//! (`shadowaead_2022/method.go`) — подробности в документе [`header`].

pub mod header;
pub mod stream;

pub use stream::{MAX_CHUNK, Ss2022Stream};
