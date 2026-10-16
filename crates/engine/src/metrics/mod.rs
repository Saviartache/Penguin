//! Учёт трафика: [`counters`] — монотонные счётчики, [`history`] — скорость.

pub mod counters;
pub mod history;

pub use counters::{Metrics, OutboundTraffic};
pub use history::{History, HistorySnapshot};
