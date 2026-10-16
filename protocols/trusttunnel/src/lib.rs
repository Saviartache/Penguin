//! TrustTunnel: `CONNECT` поверх HTTP/2 или HTTP/3, без своего рукопожатия.
//!
//! TCP — `CONNECT`, UDP — псевдо-хост `_udp2`, живость — `_check`; без ICMP.
//! Нога (`h2`/`h3`) задаётся полем `transport`, автовыбора (§3.3) нет.
//!
//! Источники: `PROTOCOL.md` v1.0 (24.12.2025) и `lib/src/` репозитория
//! `github.com/TrustTunnel/TrustTunnel` (`http_udp_codec.rs`, `net_utils.rs`,
//! `http_downstream.rs`, `settings.rs`). Единственное расхождение текста с
//! кодом (IPv4 в 16-байтовом поле, §11.2) описано в [`udp::frame`]; взят код.
//!
//! ```text
//! factory ──► outbound ──┬─► transport::link ──┬─► transport::h2
//!                        │                     └─► transport::h3
//!                        ├─► connect      (запрос CONNECT, код ответа)
//!                        └─► udp::session (поток _udp2) ──► udp::frame
//! ```
//!
//! `udp = true`, `multiplex = true`. Не реализованы: автовыбор ноги, ICMP (в
//! `Outbound` ему нет места), `user-agent` по §5.1 (см. [`connect`]), график
//! переподключения §10.3 (дело `supervisor`), отслеживание бездействия §8.4
//! (см. [`outbound`]). Сокеты выдаёт [`penguin_proto::dialer::Dialer`].

pub mod basic;
pub mod config;
pub mod connect;
pub mod error;
pub mod factory;
pub mod outbound;
pub mod transport;
pub mod udp;

pub use config::TrustTunnelConfig;
pub use error::{TrustTunnelError, TrustTunnelResult};
pub use factory::TrustTunnelFactory;
pub use outbound::TrustTunnelOutbound;

/// Имя протокола в конфигурации (менять нельзя).
pub const PROTOCOL: &str = "trusttunnel";
