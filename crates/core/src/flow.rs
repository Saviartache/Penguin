//! `FlowId` и `FlowKey`: пятёрка, по которой соединение узнаётся во всех слоях.

use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::network::Network;

/// Порядковый номер соединения внутри одного запуска.
///
/// Нужен затем, чтобы связать между собой запись в журнале, строку в
/// интерфейсе и счётчик трафика. Пятёрка для этого не годится: она
/// переиспользуется, как только система освободит локальный порт.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FlowId(u64);

impl FlowId {
    /// Следующий свободный номер.
    pub fn next() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Число внутри — для журнала.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for FlowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// Пятёрка соединения.
///
/// Ключ таблиц: по нему `netstack` находит сессию, а `process` — владельца.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// TCP или UDP.
    pub network: Network,
    /// Локальный конец.
    pub source: SocketAddr,
    /// Удалённый конец.
    pub destination: SocketAddr,
}

impl FlowKey {
    /// Собирает ключ.
    pub fn new(network: Network, source: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            network,
            source,
            destination,
        }
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} -> {}",
            self.network.as_str(),
            self.source,
            self.destination
        )
    }
}

/// Куда идут байты.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// От приложения наружу.
    Upload,
    /// Снаружи приложению.
    Download,
}
