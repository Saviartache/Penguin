//! AnyTLS: мультиплексор внутри TLS со своей схемой дополнения.
//!
//! Снаружи обычный TLS, внутри сессия с потоками по семь байт на открытие.
//! Размеры первых записей TLS задаёт схема сервера ([`padding`]).
//!
//! Следствия: ответа на опознание нет, поэтому `AuthRejected` взять неоткуда;
//! полузакрытия нет (`cmdFIN` закрывает поток целиком, `poll_shutdown` его не
//! шлёт); схема дополнения — настройка сервера, полей в форме нет.
//!
//! UDP — `udp-over-tcp` v2 из `sing-box` ([`uot`]).
//!
//! ```text
//!  factory ─► outbound ─► pool ──► connector   TLS и опознание
//!                          └────► session ─┬─► writer   дополнение записей
//!                                          ├─► reader   разбор кадров
//!                                          └─► stream   поток приложения
//!  frame, kv, padding, uot — разбор и сборка байт, без сети
//! ```
//!
//! Сокеты выдаёт [`penguin_proto::dialer::Dialer`].

pub mod config;
pub mod connector;
pub mod datagram;
pub mod error;
pub mod factory;
pub mod frame;
pub mod kv;
pub mod outbound;
pub mod padding;
pub mod pool;
pub mod reader;
pub mod session;
pub mod stream;
pub mod uot;
pub mod writer;

pub use config::AnyTlsConfig;
pub use error::{AnyTlsError, AnyTlsResult};
pub use factory::AnyTlsFactory;
pub use outbound::AnyTlsOutbound;

/// Имя протокола в конфигурации (менять нельзя).
pub const PROTOCOL: &str = "anytls";
