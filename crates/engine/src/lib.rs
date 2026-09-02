//! Сборка всего вместе: входящие -> маршрутизатор -> исходящие.
//!
//! Это тот крейт, где клиент становится клиентом. Всё остальное — части:
//! протокол умеет открыть соединение, маршрутизатор умеет решить, стек умеет
//! разобрать пакеты. Движок связывает их и отвечает за жизненный цикл.
//!
//! ```text
//!   входящая точка ──► конвейер ──┬─► маршрутизатор ──► решение
//!   (SOCKS5 / HTTP / TUN)         └─► направление ──► протокол ──► сервер
//! ```
//!
//! # Что здесь важно знать
//!
//! **Протоколы перечислены ровно в одном месте** — [`outbounds`]. Ни
//! маршрутизатор, ни стек, ни интерфейс не содержат ни строки, знающей слово
//! «hysteria».
//!
//! **Всё, что сделано с системой, откатывается** — [`tunnel`]. И откатывается
//! в обратном порядке, до конца, даже после ошибки.
//!
//! **Протокол не открывает сокетов** — [`direct`]. Иначе его пакеты уехали бы
//! в собственный, ещё не поднятый тоннель.

pub mod direct;
pub mod engine;
pub mod error;
pub mod events;
pub mod metrics;
pub mod outbounds;
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
