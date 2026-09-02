//! Кольцевой буфер скорости — источник данных для графика в GUI.
//!
//! Скорость нельзя просто спросить: счётчики монотонны и растут. Мгновенная
//! скорость — это разность двух снимков, делённая на время между ними, и
//! кто-то должен эти снимки хранить.
//!
//! Кольцо фиксированной длины: график показывает последнюю минуту, и хранить
//! больше незачем, а расти без предела память не должна.

use std::collections::VecDeque;

use penguin_core::stats::{Throughput, Traffic};
use serde::{Deserialize, Serialize};

/// Сколько отсчётов помнить.
///
/// Шестьдесят при шаге в секунду — ровно минута. Столько и показывает график.
pub const CAPACITY: usize = 60;

/// История скорости.
#[derive(Debug)]
pub struct History {
    samples: VecDeque<Throughput>,
    previous: Traffic,
    peak: Throughput,
}

impl History {
    /// Пустая история.
    pub fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(CAPACITY),
            previous: Traffic::default(),
            peak: Throughput::default(),
        }
    }

    /// Добавляет отсчёт по новому снимку счётчиков.
    ///
    /// Возвращает мгновенную скорость — её же показывает интерфейс числом.
    pub fn push(&mut self, current: Traffic, elapsed_secs: f64) -> Throughput {
        let rate = current.rate_since(&self.previous, elapsed_secs);
        self.previous = current;

        if self.samples.len() == CAPACITY {
            self.samples.pop_front();
        }
        self.samples.push_back(rate);

        self.peak = Throughput {
            up_bps: self.peak.up_bps.max(rate.up_bps),
            down_bps: self.peak.down_bps.max(rate.down_bps),
        };
        rate
    }

    /// Отсчёты от старых к новым.
    pub fn samples(&self) -> impl Iterator<Item = &Throughput> {
        self.samples.iter()
    }

    /// Последняя измеренная скорость.
    pub fn latest(&self) -> Throughput {
        self.samples.back().copied().unwrap_or_default()
    }

    /// Наибольшая скорость за сеанс.
    ///
    /// Нужна графику: без неё вертикальная шкала прыгала бы на каждом кадре,
    /// подстраиваясь под текущий максимум.
    pub fn peak(&self) -> Throughput {
        self.peak
    }

    /// Обнуляет историю — при новом подключении.
    pub fn reset(&mut self) {
        self.samples.clear();
        self.previous = Traffic::default();
        self.peak = Throughput::default();
    }

    /// Отсчёты в виде, пригодном для передачи в интерфейс.
    pub fn snapshot(&self) -> HistorySnapshot {
        HistorySnapshot {
            up: self.samples.iter().map(|s| s.up_bps).collect(),
            down: self.samples.iter().map(|s| s.down_bps).collect(),
            peak: self.peak,
        }
    }
}

impl Default for History {
    fn default() -> Self {
        Self::new()
    }
}

/// История в виде двух рядов чисел.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistorySnapshot {
    /// Отдача, байт в секунду.
    pub up: Vec<u64>,
    /// Приём, байт в секунду.
    pub down: Vec<u64>,
    /// Наибольшая скорость за сеанс — шкала графика.
    pub peak: Throughput,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn traffic(up: u64, down: u64) -> Traffic {
        Traffic {
            uploaded: up,
            downloaded: down,
            connections: 0,
        }
    }

    #[test]
    fn computes_rate_between_snapshots() {
        let mut history = History::new();
        history.push(traffic(0, 0), 1.0);
        let rate = history.push(traffic(100, 400), 1.0);
        assert_eq!(rate.up_bps, 100);
        assert_eq!(rate.down_bps, 400);
    }

    #[test]
    fn keeps_only_the_last_minute() {
        let mut history = History::new();
        for step in 0..(CAPACITY as u64 * 3) {
            history.push(traffic(step * 10, 0), 1.0);
        }
        assert_eq!(history.samples().count(), CAPACITY);
    }

    #[test]
    fn remembers_the_peak() {
        // Без этого вертикальная шкала графика прыгала бы на каждом кадре.
        let mut history = History::new();
        history.push(traffic(0, 0), 1.0);
        history.push(traffic(0, 5_000), 1.0);
        history.push(traffic(0, 5_100), 1.0);
        assert_eq!(history.peak().down_bps, 5_000);
        assert_eq!(history.latest().down_bps, 100);
    }

    #[test]
    fn counter_reset_does_not_spike_the_graph() {
        // При переподключении счётчики обнуляются; разность стала бы
        // отрицательной, а на беззнаковых — гигантской.
        let mut history = History::new();
        history.push(traffic(1_000_000, 1_000_000), 1.0);
        let after_reset = history.push(traffic(0, 0), 1.0);
        assert_eq!(after_reset, Throughput::default());
    }

    #[test]
    fn snapshot_has_matching_rows() {
        let mut history = History::new();
        for step in 0..5 {
            history.push(traffic(step * 100, step * 200), 1.0);
        }
        let snapshot = history.snapshot();
        assert_eq!(snapshot.up.len(), snapshot.down.len());
        assert_eq!(snapshot.up.len(), 5);
    }

    #[test]
    fn reset_clears_everything() {
        let mut history = History::new();
        history.push(traffic(100, 100), 1.0);
        history.reset();
        assert_eq!(history.samples().count(), 0);
        assert_eq!(history.peak(), Throughput::default());
    }
}
