//! Pingwin — свой протокол Penguin поверх HTTP/3, а где UDP режут — поверх HTTP/2.
//!
//! На проводе - обычный TLS 1.3: QUIC с ALPN `h3` или TCP с ALPN `h2`, оба на 443.
//! Опознание ключом X25519 привязано к экспорту TLS, чужому сервер отвечает
//! статическим сайтом. Одно соединение на профиль: потоки - `CONNECT`, UDP -
//! датаграммы QUIC или капсулы в потоке. Формат - `.obsidian-penguin/Pingwin/`.
//!
//! ```text
//! factory ──► outbound ──► connection ──┬─► session (QUIC) ─┬─► stream    поток CONNECT
//!                          (auto: гонка) └─► tcp (HTTP/2) ───┴─► datagram  канал connect-udp
//! wire/  формат (общий с сервером)    link  ссылка-приглашение
//! ```
//!
//! Без 0-RTT и смены порта. Сокеты выдаёт `Dialer`.

pub mod config;
mod connection;
pub mod datagram;
pub mod error;
pub mod factory;
pub mod link;
pub mod outbound;
mod session;
pub mod stream;
pub mod tcp;
pub mod wire;

pub use config::{PingwinConfig, Transport};
pub use error::{PingwinError, PingwinResult};
pub use factory::PingwinFactory;
pub use outbound::PingwinOutbound;
pub use wire::keys::StaticKeyPair;

/// Имя протокола в конфигурации (менять нельзя).
pub const PROTOCOL: &str = "pingwin";
