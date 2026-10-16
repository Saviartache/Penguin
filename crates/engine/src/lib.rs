//! Сборка всего вместе: входящие -> маршрутизатор -> исходящие.
//!
//! ```text
//!   входящая точка ──► конвейер ──┬─► маршрутизатор ──► решение
//!   (SOCKS5 / HTTP / TUN)         └─► направление ──► протокол ──► сервер
//! ```
//!
//! Протоколы перечислены только в [`outbounds`]; откат системных изменений —
//! в [`tunnel`]; сокеты протоколов выдаёт [`direct`].

pub mod direct;
pub mod engine;
pub mod error;
pub mod events;
pub mod metrics;
pub mod outbounds;
pub mod packet;
pub mod packet_dns;
pub mod packet_tunnel;
pub mod pipeline;
pub mod sniff;
pub mod state;
pub mod supervisor;
pub mod tunnel;

pub use direct::{DirectOutbound, SystemDialer};
pub use engine::Engine;
pub use error::{EngineError, EngineResult};
pub use events::{Event, EventBus, LogLevel};
pub use metrics::{History, Metrics};
pub use outbounds::OutboundPool;
pub use pipeline::Pipeline;
pub use state::StateMachine;
pub use tunnel::TunnelSession;
