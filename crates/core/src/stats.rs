//! Счётчики трафика, мгновенная скорость, RTT.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

/// Разделяемые счётчики трафика.
///
/// Атомарные, а не под мьютексом: их обновляет каждый скопированный блок
/// байт из сотен соединений сразу, и мьютекс здесь стал бы точкой сборки всей
/// программы. `Relaxed` достаточно — порядок между счётчиками не важен,
/// важна только сумма.
#[derive(Debug, Default)]
pub struct Counters {
    uploaded: AtomicU64,
    downloaded: AtomicU64,
    connections: AtomicU64,
}

impl Counters {
    /// Новый набор счётчиков.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Учитывает отправленные байты.
    pub fn add_uploaded(&self, bytes: u64) {
        self.uploaded.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Учитывает принятые байты.
    pub fn add_downloaded(&self, bytes: u64) {
        self.downloaded.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Учитывает открытое соединение.
    pub fn add_connection(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Снимок на текущий момент.
    pub fn snapshot(&self) -> Traffic {
        Traffic {
            uploaded: self.uploaded.load(Ordering::Relaxed),
            downloaded: self.downloaded.load(Ordering::Relaxed),
            connections: self.connections.load(Ordering::Relaxed),
        }
    }

    /// Обнуляет счётчики — при новом подключении.
    pub fn reset(&self) {
        self.uploaded.store(0, Ordering::Relaxed);
        self.downloaded.store(0, Ordering::Relaxed);
        self.connections.store(0, Ordering::Relaxed);
    }
}

/// Снимок счётчиков.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Traffic {
    /// Отправлено байт.
    pub uploaded: u64,
    /// Принято байт.
    pub downloaded: u64,
    /// Открыто соединений с начала сеанса.
    pub connections: u64,
}

impl Traffic {
    /// Всего байт в обе стороны.
    pub fn total(&self) -> u64 {
        self.uploaded + self.downloaded
    }

    /// Скорость между двумя снимками.
    ///
    /// Счётчики монотонны, но между снимками мог случиться сброс при
    /// переподключении — тогда разность отрицательна, и вместо неё берётся
    /// ноль, а не переполнение до величины в эксабайтах.
    pub fn rate_since(&self, previous: &Self, elapsed_secs: f64) -> Throughput {
        if elapsed_secs <= 0.0 {
            return Throughput::default();
        }
        Throughput {
            up_bps: (self.uploaded.saturating_sub(previous.uploaded) as f64 / elapsed_secs) as u64,
            down_bps: (self.downloaded.saturating_sub(previous.downloaded) as f64 / elapsed_secs)
                as u64,
        }
    }
}

/// Мгновенная скорость в байтах в секунду.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Throughput {
    /// Отдача.
    pub up_bps: u64,
    /// Приём.
    pub down_bps: u64,
}

/// Время оборота до сервера.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rtt {
    /// Миллисекунды.
    pub millis: u32,
}

impl Rtt {
    /// Из миллисекунд.
    pub fn from_millis(millis: u32) -> Self {
        Self { millis }
    }
}

/// Переводит байты в строку с приставкой: `1.4 МБ`.
///
/// Отдельная функция, а не метод: форматирование нужно и счётчикам, и
/// скорости, и размеру файла подписки.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_bytes() {
        assert_eq!(format_bytes(512), "512 Б");
        assert_eq!(format_bytes(1536), "1.5 КБ");
        assert_eq!(format_bytes(1024 * 1024 * 3 / 2), "1.5 МБ");
    }

    #[test]
    fn rate_survives_counter_reset() {
        let before = Traffic {
            uploaded: 1_000,
            downloaded: 2_000,
            connections: 1,
        };
        let after = Traffic {
            uploaded: 0,
            downloaded: 0,
            connections: 0,
        };
        // Сброс не должен превращаться в скорость размером с адресное пространство.
        assert_eq!(after.rate_since(&before, 1.0), Throughput::default());
    }

    #[test]
    fn computes_rate() {
        let before = Traffic::default();
        let after = Traffic {
            uploaded: 100,
            downloaded: 400,
            connections: 0,
        };
        let rate = after.rate_since(&before, 2.0);
        assert_eq!(rate.up_bps, 50);
        assert_eq!(rate.down_bps, 200);
    }
}
