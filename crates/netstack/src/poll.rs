//! Таймеры smoltcp и пробуждения. Опрос по расписанию стека, а не в цикле
//! без сна.
//!
//! У smoltcp свои часы: перепосылка, задержанные подтверждения, закрытие по
//! таймауту. Он сам говорит, когда его разбудить следующий раз
//! (`poll_delay`), и это единственный правильный способ его крутить.
//!
//! Опрос в цикле без сна съел бы ядро процессора на простаивающем тоннеле;
//! опрос по своему таймеру — либо то же самое при мелком шаге, либо
//! задержки в секунды при крупном.

use std::time::{Duration, Instant};

/// Наибольшая пауза между опросами.
///
/// Даже когда стеку ничего не нужно, просыпаться иногда надо: за это время
/// могли прийти данные из очередей движка, о которых smoltcp не знает.
pub const MAX_IDLE: Duration = Duration::from_millis(200);

/// Наименьшая пауза.
///
/// Ноль от smoltcp означает «есть что делать прямо сейчас», но крутиться без
/// передышки нельзя: задачи движка тоже должны получить время.
pub const MIN_DELAY: Duration = Duration::from_millis(1);

/// Момент запуска — точка отсчёта часов smoltcp.
///
/// Свои часы, а не системные: перевод времени не должен ломать таймеры
/// перепосылки посреди работы.
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

/// Приводит паузу от smoltcp к разумным пределам.
pub fn clamp_delay(delay: Option<smoltcp::time::Duration>) -> Duration {
    match delay {
        // `total_micros`, а не `micros`: второй отдаёт только доли секунды,
        // и минутная пауза превратилась бы в миллисекундную — то есть в
        // опрос без сна на простаивающем тоннеле.
        Some(delay) => Duration::from_micros(delay.total_micros()).clamp(MIN_DELAY, MAX_IDLE),
        // Стеку ничего не нужно — спим до предела.
        None => MAX_IDLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_delay_still_yields() {
        // Ноль означает «есть что делать», но крутиться без передышки нельзя:
        // остальным задачам тоже нужно время.
        let delay = clamp_delay(Some(smoltcp::time::Duration::ZERO));
        assert_eq!(delay, MIN_DELAY);
        assert!(delay > Duration::ZERO);
    }

    #[test]
    fn long_delay_is_capped() {
        // Даже когда стеку ничего не нужно, просыпаться надо: данные из
        // очередей движка он не видит.
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
