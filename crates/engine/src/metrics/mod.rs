//! Учёт трафика и скорости.
//!
//! Две разные вещи, и путать их не надо. [`counters`] — монотонные счётчики:
//! сколько байт прошло всего и через какое направление. [`history`] — скорость,
//! то есть разность двух снимков счётчиков за известное время.

pub mod counters;
pub mod history;

pub use counters::{Metrics, OutboundTraffic};
pub use history::{History, HistorySnapshot};
