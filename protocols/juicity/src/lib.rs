//! Juicity: QUIC без датаграмм, всё потоками.
//!
//! Родственник TUIC (опознание по UUID и паролю, отпечаток из ключевого
//! материала TLS), но без датаграмм QUIC и команд; UDP едет одним надёжным потоком.
//!
//! - Отказ сервер сообщает кодом [`AUTH_FAILED`](link::AUTH_FAILED), поэтому есть `AuthRejected`.
//! - Соединений несколько: тридцать потоков на каждое (см. [`link`]).
//! - Спецификация врёт про нумерацию адреса: эталон использует SOCKS5 ([`frame::proxy`]).
//!
//! ```text
//!  factory ─► outbound ─► pool ──► link ──► опознание, счёт потоков
//!                          │
//!                          ├────► stream    поток приложения
//!                          └────► datagram  датаграммы одним потоком
//!  frame — разбор и сборка байт, без сети
//! ```
//!
//! Сокеты выдаёт [`penguin_proto::dialer::Dialer`].

pub mod config;
pub mod datagram;
pub mod error;
pub mod factory;
pub mod frame;
pub mod link;
pub mod outbound;
pub mod pool;
pub mod stream;

pub use config::JuicityConfig;
pub use error::{JuicityError, JuicityResult};
pub use factory::JuicityFactory;
pub use outbound::JuicityOutbound;

/// Имя протокола в конфигурации; менять нельзя.
pub const PROTOCOL: &str = "juicity";
