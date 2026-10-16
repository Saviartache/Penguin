//! Монотонные часы за трейтом — чтобы тесты не ждали настоящих секунд.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Источник времени: тесты двигают его сами, не ожидая секунд.
pub trait Clock: Send + Sync + 'static {
    /// Сколько прошло с момента создания часов.
    fn elapsed(&self) -> Duration;
}

/// Настоящие часы.
#[derive(Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// Заводит часы от текущего момента.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            origin: Instant::now(),
        })
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn elapsed(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// Часы, которые двигает тест.
#[derive(Debug, Default)]
pub struct TestClock {
    millis: AtomicU64,
}

impl TestClock {
    /// Заводит часы на нуле.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Двигает время вперёд.
    pub fn advance(&self, by: Duration) {
        self.millis
            .fetch_add(by.as_millis() as u64, Ordering::Relaxed);
    }
}

impl Clock for TestClock {
    fn elapsed(&self) -> Duration {
        Duration::from_millis(self.millis.load(Ordering::Relaxed))
    }
}

/// Задержка перед следующей попыткой: удвоение с потолком, без дрожания.
pub fn backoff(attempt: u32, base: Duration, max: Duration) -> Duration {
    let factor = 1u64 << attempt.min(16);
    base.saturating_mul(factor as u32).min(max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_then_stops() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(30);
        assert_eq!(backoff(0, base, max), Duration::from_secs(1));
        assert_eq!(backoff(3, base, max), Duration::from_secs(8));
        assert_eq!(backoff(10, base, max), max);
        assert_eq!(backoff(u32::MAX, base, max), max);
    }

    #[test]
    fn test_clock_advances() {
        let clock = TestClock::new();
        assert_eq!(clock.elapsed(), Duration::ZERO);
        clock.advance(Duration::from_secs(90));
        assert_eq!(clock.elapsed(), Duration::from_secs(90));
    }
}
