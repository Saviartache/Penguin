//! Hysteria 2: прокси поверх QUIC с маскировкой под HTTP/3.
//!
//! Сервер — настоящий HTTP/3: пропуск — заголовок `Hysteria-Auth`, успех — код 233 (см. [`auth`]).
//! [`congestion::brutal`] держит заданную скорость, при потерях шлёт быстрее.
//! Необязательно: [`transport::obfs`] (обфускация пакетов), [`transport::hop`] (смена порта).
//! Сокеты выдаёт [`penguin_proto::dialer::Dialer`].
//!
//! ```text
//!  factory ──► client ──┬─► auth        аутентификация HTTP/3
//!                       ├─► session/tcp поток на прикладное соединение
//!                       ├─► session/udp датаграммы, разобранные по сессиям
//!                       └─► transport   QUIC, обфускация, смена порта
//!                            └─► congestion/brutal
//!  frame — разбор и сборка байт, ничего не знает об остальном
//! ```

pub mod auth;
pub mod client;
pub mod config;
pub mod congestion;
pub mod error;
pub mod factory;
pub mod frame;
pub mod session;
pub mod transport;

pub use client::Hysteria2Client;
pub use config::Hysteria2Config;
pub use error::{Hysteria2Error, Hysteria2Result};
pub use factory::Hysteria2Factory;

/// Имя протокола в конфигурации; менять нельзя.
pub const PROTOCOL: &str = "hysteria2";
