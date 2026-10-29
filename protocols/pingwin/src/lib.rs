//! Pingwin — свой протокол Penguin поверх HTTP/3.
//!
//! На проводе - обычный QUIC/TLS 1.3 с ALPN `h3`; опознание ключом X25519 привязано
//! к экспорту TLS, чужому сервер отвечает статическим сайтом. Одно соединение на
//! профиль: потоки - `CONNECT`, UDP - датаграммы. Формат - `.obsidian-penguin/Pingwin/`.
//!
//! ```text
//! factory ──► outbound ──► session ──┬─► stream    поток CONNECT
//!                                    └─► datagram  канал connect-udp
//! wire/  формат (общий с сервером)    link  ссылка-приглашение
//! ```
//!
//! Без 0-RTT и смены порта. Сокеты выдаёт `Dialer`.

pub mod config;
pub mod datagram;
pub mod error;
pub mod factory;
pub mod link;
pub mod outbound;
mod session;
pub mod stream;
pub mod wire;

pub use config::PingwinConfig;
pub use error::{PingwinError, PingwinResult};
pub use factory::PingwinFactory;
pub use outbound::PingwinOutbound;
pub use wire::keys::StaticKeyPair;

/// Имя протокола в конфигурации (менять нельзя).
pub const PROTOCOL: &str = "pingwin";
