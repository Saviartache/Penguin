//! TUIC v5: QUIC, всё шифрование — TLS внутри QUIC.
//!
//! - Отпечаток проверки подлинности привязан к соединению (экспорт ключевого
//!   материала TLS, метка — 16 сырых байт UUID); ответа сервер не шлёт.
//! - Запись адреса своя ([`frame::address`]): нумерация не совпадает с `socks` и `v2ray`.
//! - Соединение постоянное, одно на профиль (`multiplex: true`); переподнимает его `supervisor`.
//! - Датаграммы: `native` (датаграммы QUIC с разрезанием по MTU) или `quic`
//!   (односторонние потоки). Сборка частей общая (`penguin_transport::frag`).
//!
//! Константы взяты из `EAimTY/tuic` (`SPEC.md`) и `SagerNet/sing-quic`.

pub mod config;
pub mod datagram;
pub mod error;
pub mod factory;
pub mod frame;
pub mod outbound;
pub mod session;
pub mod stream;
pub mod transport;

pub use config::{Congestion, TuicConfig, UdpMode};
pub use error::{TuicError, TuicResult};
pub use factory::TuicFactory;
pub use outbound::TuicOutbound;

/// Имя протокола в конфигурации; менять нельзя.
pub const PROTOCOL: &str = "tuic";
