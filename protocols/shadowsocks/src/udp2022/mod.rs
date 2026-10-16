//! UDP Shadowsocks 2022: идентификатор сессии и счётчик пакета вместо соли.
//!
//! ```text
//!  header    раскладка тела датаграммы
//!  cipher    разовые шифры датаграммы (AES-GCM и ChaCha)
//!  datagram  канал: сборка, разбор, сокет
//! ```

pub mod cipher;
pub mod datagram;
pub mod header;

pub use datagram::ShadowsocksDatagram2022;
