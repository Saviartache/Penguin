//! Смена порта по расписанию.
//!
//! Ограничение скорости у провайдера обычно навешивается на поток, опознанный
//! по пятёрке. Смена порта делает из одного потока череду коротких: каждые
//! несколько десятков секунд пятёрка новая, и счётчик начинается заново.
//!
//! Сервер при этом слушает весь диапазон — обычно одним правилом
//! перенаправления, — так что для него ничего не меняется.
//!
//! Часов и фоновой задачи здесь нет: текущий порт — чистая функция от
//! прошедшего времени. Это не экономия, а свойство: любой поток может
//! спросить порт когда угодно и получит тот же ответ, без общей блокировки на
//! горячем пути отправки.

use std::time::{Duration, Instant};

use penguin_core::endpoint::PortSpec;

/// Выбор порта по времени.
#[derive(Debug)]
pub struct PortHopper {
    ports: PortSpec,
    interval: Duration,
    origin: Instant,
}

impl PortHopper {
    /// Заводит смену порта.
    ///
    /// `None`, если порт всего один: тогда и менять нечего, а лишняя проверка
    /// на пути каждого пакета не нужна.
    pub fn new(ports: PortSpec, interval: Duration) -> Option<Self> {
        if !ports.is_hopping() {
            return None;
        }
        Some(Self {
            ports,
            interval: interval.max(Duration::from_secs(1)),
            origin: Instant::now(),
        })
    }

    /// Порт на текущий момент.
    pub fn current(&self) -> u16 {
        self.port_at(self.origin.elapsed())
    }

    /// Порт по прошедшему времени. Вынесено ради тестов, которым нельзя ждать.
    fn port_at(&self, elapsed: Duration) -> u16 {
        let step = elapsed.as_secs() / self.interval.as_secs().max(1);
        self.ports.nth(scatter(step) as u32)
    }

    /// Сколько портов в наборе.
    pub fn port_count(&self) -> u32 {
        self.ports.count()
    }
}

/// Перемешивает номер шага.
///
/// Без этого порты обходились бы подряд, и наблюдателю, увидевшему два
/// перехода, третий известен заранее. Здесь splitmix64 — не ради стойкости, а
/// ради того, чтобы соседние шаги давали далёкие друг от друга числа.
fn scatter(step: u64) -> u64 {
    let mut z = step.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hopper(spec: &str, secs: u64) -> PortHopper {
        PortHopper::new(spec.parse().expect("порты"), Duration::from_secs(secs))
            .expect("диапазон задан")
    }

    #[test]
    fn single_port_needs_no_hopping() {
        assert!(PortHopper::new(PortSpec::Single(443), Duration::from_secs(30)).is_none());
    }

    #[test]
    fn port_stays_put_within_one_interval() {
        let hopper = hopper("20000-20100", 30);
        let first = hopper.port_at(Duration::from_secs(0));
        assert_eq!(hopper.port_at(Duration::from_secs(29)), first);
        // На границе интервала порт обязан смениться... почти всегда: с
        // вероятностью 1/101 новый шаг попадёт в тот же порт, и это не сбой.
        let next = hopper.port_at(Duration::from_secs(30));
        assert_eq!(hopper.port_at(Duration::from_secs(59)), next);
    }

    #[test]
    fn ports_stay_inside_the_range() {
        let hopper = hopper("20000-30000", 30);
        for step in 0..10_000u64 {
            let port = hopper.port_at(Duration::from_secs(step * 30));
            assert!((20000..=30000).contains(&port), "порт {port} вне диапазона");
        }
    }

    #[test]
    fn walk_is_not_sequential() {
        // Подряд идущие порты выдали бы расписание наблюдателю после двух
        // переходов.
        let hopper = hopper("20000-30000", 30);
        let walk: Vec<u16> = (0..10)
            .map(|s| hopper.port_at(Duration::from_secs(s * 30)))
            .collect();
        let sequential = walk.windows(2).all(|w| w[1] == w[0] + 1);
        assert!(!sequential);
    }

    #[test]
    fn covers_the_range_reasonably() {
        // Разброс должен быть настоящим, а не парой любимых значений.
        let hopper = hopper("20000-20099", 1);
        let seen: std::collections::HashSet<u16> = (0..2000u64)
            .map(|s| hopper.port_at(Duration::from_secs(s)))
            .collect();
        assert!(seen.len() > 80, "использовано портов: {}", seen.len());
    }

    #[test]
    fn zero_interval_does_not_divide_by_zero() {
        let hopper = hopper("20000-20100", 0);
        // Ноль поднимается до секунды при создании.
        let _ = hopper.port_at(Duration::from_secs(5));
    }
}
