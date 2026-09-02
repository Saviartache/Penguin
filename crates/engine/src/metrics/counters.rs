//! Счётчики: суммарно, по профилю, по процессу.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use penguin_core::id::OutboundId;
use penguin_core::stats::{Counters, Traffic};
use serde::{Deserialize, Serialize};

/// Учёт трафика по всему клиенту и по направлениям.
#[derive(Debug, Default)]
pub struct Metrics {
    total: Counters,
    by_outbound: DashMap<OutboundId, Arc<Counters>>,
    live_connections: AtomicU64,
}

impl Metrics {
    /// Пустой учёт.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Счётчики направления.
    ///
    /// Создаются при первом обращении: направлений немного, а заводить их
    /// заранее пришлось бы при каждом изменении списка профилей.
    pub fn outbound(&self, id: &OutboundId) -> Arc<Counters> {
        if let Some(existing) = self.by_outbound.get(id) {
            return Arc::clone(&existing);
        }
        let counters = Counters::new();
        self.by_outbound.insert(id.clone(), Arc::clone(&counters));
        counters
    }

    /// Общие счётчики.
    pub fn total(&self) -> Traffic {
        self.total.snapshot()
    }

    /// Учитывает отправленные байты.
    pub fn add_uploaded(&self, outbound: &OutboundId, bytes: u64) {
        self.total.add_uploaded(bytes);
        self.outbound(outbound).add_uploaded(bytes);
    }

    /// Учитывает принятые байты.
    pub fn add_downloaded(&self, outbound: &OutboundId, bytes: u64) {
        self.total.add_downloaded(bytes);
        self.outbound(outbound).add_downloaded(bytes);
    }

    /// Соединение открылось.
    pub fn connection_opened(&self, outbound: &OutboundId) {
        self.total.add_connection();
        self.outbound(outbound).add_connection();
        self.live_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Соединение закрылось.
    pub fn connection_closed(&self) {
        // `fetch_update`, а не `fetch_sub`: счётчик беззнаковый, и лишнее
        // закрытие увело бы его в число размером с адресное пространство.
        let _ = self
            .live_connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
                Some(live.saturating_sub(1))
            });
    }

    /// Сколько соединений открыто прямо сейчас.
    pub fn live_connections(&self) -> u64 {
        self.live_connections.load(Ordering::Relaxed)
    }

    /// Снимок по каждому направлению.
    pub fn per_outbound(&self) -> Vec<OutboundTraffic> {
        let mut rows: Vec<OutboundTraffic> = self
            .by_outbound
            .iter()
            .map(|entry| OutboundTraffic {
                outbound: entry.key().to_string(),
                traffic: entry.value().snapshot(),
            })
            .collect();
        rows.sort_by(|a, b| b.traffic.total().cmp(&a.traffic.total()));
        rows
    }

    /// Обнуляет всё — при новом подключении.
    pub fn reset(&self) {
        self.total.reset();
        for entry in self.by_outbound.iter() {
            entry.value().reset();
        }
        self.live_connections.store(0, Ordering::Relaxed);
    }
}

/// Трафик одного направления.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundTraffic {
    /// Имя направления.
    pub outbound: String,
    /// Что через него прошло.
    pub traffic: Traffic,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(name: &str) -> OutboundId {
        OutboundId::new(name)
    }

    #[test]
    fn counts_globally_and_per_outbound() {
        let metrics = Metrics::new();
        metrics.add_uploaded(&id("home"), 100);
        metrics.add_downloaded(&id("home"), 400);
        metrics.add_uploaded(&id("direct"), 50);

        assert_eq!(metrics.total().uploaded, 150);
        assert_eq!(metrics.total().downloaded, 400);
        assert_eq!(metrics.outbound(&id("home")).snapshot().uploaded, 100);
        assert_eq!(metrics.outbound(&id("direct")).snapshot().uploaded, 50);
    }

    #[test]
    fn live_connections_never_go_negative() {
        // Лишнее закрытие увело бы беззнаковый счётчик в число размером с
        // адресное пространство, и интерфейс показал бы 18 квинтиллионов
        // соединений.
        let metrics = Metrics::new();
        metrics.connection_opened(&id("home"));
        metrics.connection_closed();
        metrics.connection_closed();
        assert_eq!(metrics.live_connections(), 0);
    }

    #[test]
    fn per_outbound_is_sorted_by_volume() {
        let metrics = Metrics::new();
        metrics.add_downloaded(&id("тихий"), 10);
        metrics.add_downloaded(&id("шумный"), 1000);

        let rows = metrics.per_outbound();
        assert_eq!(rows[0].outbound, "шумный");
    }

    #[test]
    fn reset_clears_everything() {
        let metrics = Metrics::new();
        metrics.connection_opened(&id("home"));
        metrics.add_uploaded(&id("home"), 100);
        metrics.reset();

        assert_eq!(metrics.total().uploaded, 0);
        assert_eq!(metrics.live_connections(), 0);
        assert_eq!(metrics.outbound(&id("home")).snapshot().uploaded, 0);
    }
}
