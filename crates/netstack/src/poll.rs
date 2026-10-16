//! Часы и паузы опроса smoltcp: стек просыпается по `poll_delay`, а не в цикле без сна.

use std::time::{Duration, Instant};

/// Наибольшая пауза между опросами.
pub const MAX_IDLE: Duration = Duration::from_millis(200);

/// Наименьшая пауза: нулевая задержка smoltcp не должна отнимать время у остальных задач.
pub const MIN_DELAY: Duration = Duration::from_millis(1);

/// Часы smoltcp от момента запуска (не системные: перевод времени не должен ломать перепосылку).
#[derive(Debug, Clone, Copy)]
pub struct Clock {
    origin: Instant,
}

impl Clock {
    /// Запускает часы.
    pub fn start() -> Self {
        Self {
            origin: Instant::now(),
        }
    }

    /// Текущий момент в понятиях smoltcp.
    pub fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_micros(self.origin.elapsed().as_micros() as i64)
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::start()
    }
}

/// Приводит паузу от smoltcp к пределам [`MIN_DELAY`]..[`MAX_IDLE`].
pub fn clamp_delay(delay: Option<smoltcp::time::Duration>) -> Duration {
    match delay {
        // `total_micros`: `micros` отдаёт только доли секунды.
        Some(delay) => Duration::from_micros(delay.total_micros()).clamp(MIN_DELAY, MAX_IDLE),
        None => MAX_IDLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_delay_still_yields() {
        let delay = clamp_delay(Some(smoltcp::time::Duration::ZERO));
        assert_eq!(delay, MIN_DELAY);
        assert!(delay > Duration::ZERO);
    }

    #[test]
    fn long_delay_is_capped() {
        let delay = clamp_delay(Some(smoltcp::time::Duration::from_secs(60)));
        assert_eq!(delay, MAX_IDLE);
    }

    #[test]
    fn no_deadline_means_idle_cap() {
        assert_eq!(clamp_delay(None), MAX_IDLE);
    }

    #[test]
    fn moderate_delay_passes_through() {
        let delay = clamp_delay(Some(smoltcp::time::Duration::from_millis(50)));
        assert_eq!(delay, Duration::from_millis(50));
    }

    #[test]
    fn clock_moves_forward() {
        let clock = Clock::start();
        let first = clock.now();
        std::thread::sleep(Duration::from_millis(2));
        assert!(clock.now() > first);
    }
}
