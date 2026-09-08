//! UDP Shadowsocks 2022: свой идентификатор сессии и счётчик пакета вместо
//! соли на каждой посылке.
//!
//! ```text
//!  header    байтовая раскладка тела датаграммы — без шифрования, без сети
//!  cipher    разовые шифры одной датаграммы — свои у AES-GCM и у ChaCha
//!  datagram  сам канал: сборка, разбор, сокет
//! ```
//!
//! Устройство и раскладка байт сверены построчно с `shadowsocks-rust`
//! (`crates/shadowsocks/src/relay/udprelay/aead_2022.rs`) и независимо с
//! `sing-shadowsocks2` (`shadowaead_2022/method.go`) — подробности в
//! документах [`header`] и [`cipher`].

pub mod cipher;
pub mod datagram;
pub mod header;

pub use datagram::ShadowsocksDatagram2022;
