//! Brutal: заданная скорость вместо реакции на потери (`Controller` из quinn).
//! Окно = `bps · rtt / ack_rate`: потери увеличивают темп, чтобы дошедшая
//! скорость осталась заданной.
//!
//! В Go окно берётся с двукратным запасом, а темп держит свой пейсер. У quinn
//! пейсер пополняется со скоростью `окно · 1.25 / rtt`, поэтому множитель
//! здесь единица: темп ограничивает окно.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerFactory};
use quinn_proto::RttEstimator;

/// Сколько односекундных отсчётов помнить.
const SLOT_COUNT: u64 = 5;

/// Минимум пакетов, при котором доля дошедших что-то значит.
const MIN_SAMPLES: u64 = 50;

/// Нижняя граница доли дошедших: при обрыве окно не должно расти без предела.
const MIN_ACK_RATE: f64 = 0.8;

/// Окно, пока задержка ещё не измерена.
const INITIAL_WINDOW: u64 = 10_240;

/// Отсчёт за одну секунду.
#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    second: u64,
    acked: u64,
    lost: u64,
}

/// Доля дошедших пакетов за последние `SLOT_COUNT` секунд; без сети и часов.
#[derive(Debug)]
pub struct RateTracker {
    slots: [Slot; SLOT_COUNT as usize],
    ack_rate: f64,
}

impl RateTracker {
    /// Пустой счётчик. Пока потерь не видели, доля равна единице.
    pub fn new() -> Self {
        Self {
            slots: [Slot::default(); SLOT_COUNT as usize],
            ack_rate: 1.0,
        }
    }

    /// Учитывает дошедший пакет.
    pub fn record_ack(&mut self, second: u64) {
        let slot = self.slot_for(second);
        slot.acked += 1;
        self.recompute(second);
    }

    /// Учитывает потерянный пакет.
    pub fn record_loss(&mut self, second: u64) {
        let slot = self.slot_for(second);
        slot.lost += 1;
        self.recompute(second);
    }

    /// Текущая доля дошедших.
    pub fn ack_rate(&self) -> f64 {
        self.ack_rate
    }

    /// Ячейка кольца под секунду; устаревшая обнуляется.
    fn slot_for(&mut self, second: u64) -> &mut Slot {
        let index = (second % SLOT_COUNT) as usize;
        let slot = &mut self.slots[index];
        if slot.second != second {
            *slot = Slot {
                second,
                acked: 0,
                lost: 0,
            };
        }
        slot
    }

    fn recompute(&mut self, now: u64) {
        let oldest = now.saturating_sub(SLOT_COUNT);
        let (acked, lost) = self
            .slots
            .iter()
            .filter(|slot| slot.second >= oldest)
            .fold((0u64, 0u64), |(a, l), slot| (a + slot.acked, l + slot.lost));

        let total = acked + lost;
        self.ack_rate = if total < MIN_SAMPLES {
            1.0
        } else {
            (acked as f64 / total as f64).max(MIN_ACK_RATE)
        };
    }
}

impl Default for RateTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Считает окно перегрузки.
pub fn congestion_window(bytes_per_second: u64, rtt: Duration, ack_rate: f64, mtu: u16) -> u64 {
    if rtt.is_zero() || bytes_per_second == 0 {
        return INITIAL_WINDOW;
    }
    let rate = ack_rate.max(MIN_ACK_RATE);
    let window = bytes_per_second as f64 * rtt.as_secs_f64() / rate;

    // Пол в два кадра: меньшее окно останавливает отправку.
    let floor = u64::from(mtu) * 2;
    (window as u64).max(floor)
}

/// Скорость Brutal, разделяемая и изменяемая на ходу: сервер ограничивает её
/// после аутентификации (`Hysteria-CC-RX`), а контроллер у живого соединения не сменить.
#[derive(Debug, Clone)]
pub struct BrutalRate(Arc<AtomicU64>);

impl BrutalRate {
    /// Из скорости в байтах в секунду (как в `Hysteria-CC-RX`).
    pub fn new(bytes_per_second: u64) -> Self {
        Self(Arc::new(AtomicU64::new(bytes_per_second)))
    }

    /// Из скорости в битах в секунду — так её задаёт пользователь.
    pub fn from_bits_per_second(bits: u64) -> Self {
        Self::new(bits / 8)
    }

    /// Текущая скорость в байтах в секунду.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    /// Задаёт скорость.
    pub fn set(&self, bytes_per_second: u64) {
        self.0.store(bytes_per_second, Ordering::Relaxed);
    }

    /// Опускает скорость до указанной, если та ниже; ноль («без ограничений») обрабатывает вызывающий.
    pub fn cap_to(&self, bytes_per_second: u64) {
        self.0.fetch_min(bytes_per_second, Ordering::Relaxed);
    }
}

/// Настройки Brutal.
#[derive(Debug, Clone)]
pub struct BrutalConfig {
    /// Скорость, общая с живым контроллером.
    pub rate: BrutalRate,
}

impl BrutalConfig {
    /// Из скорости в битах в секунду.
    pub fn from_bits_per_second(bits: u64) -> Self {
        Self {
            rate: BrutalRate::from_bits_per_second(bits),
        }
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal::new(self.rate.clone(), current_mtu))
    }
}

/// Управление перегрузкой Brutal.
#[derive(Debug)]
pub struct Brutal {
    rate: BrutalRate,
    mtu: u16,
    rtt: Duration,
    origin: Option<Instant>,
    tracker: RateTracker,
}

impl Brutal {
    /// Создаёт управление с заданной скоростью.
    pub fn new(rate: BrutalRate, mtu: u16) -> Self {
        Self {
            rate,
            mtu,
            rtt: Duration::ZERO,
            origin: None,
            tracker: RateTracker::new(),
        }
    }

    /// Номер секунды с начала соединения (не системные часы).
    fn second_of(&mut self, now: Instant) -> u64 {
        let origin = *self.origin.get_or_insert(now);
        now.saturating_duration_since(origin).as_secs()
    }
}

impl Controller for Brutal {
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        // Как в эталоне: максимум из сглаженной и последней задержки.
        self.rtt = rtt.conservative();
        let second = self.second_of(now);
        self.tracker.record_ack(second);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // ECN-события без потерянных байт не считаются потерей.
        if lost_bytes == 0 {
            return;
        }
        let second = self.second_of(now);
        self.tracker.record_loss(second);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
    }

    fn window(&self) -> u64 {
        congestion_window(self.rate.get(), self.rtt, self.tracker.ack_rate(), self.mtu)
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Brutal::new(self.rate.clone(), self.mtu))
    }

    fn initial_window(&self) -> u64 {
        INITIAL_WINDOW
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MTU: u16 = 1280;

    #[test]
    fn window_is_bandwidth_delay_product() {
        // 12 500 000 Б/с — это 100 Мбит/с. При задержке 100 мс в полёте должно
        // находиться 1 250 000 байт, иначе канал не заполнится.
        let window = congestion_window(12_500_000, Duration::from_millis(100), 1.0, MTU);
        assert_eq!(window, 1_250_000);
    }

    #[test]
    fn window_grows_when_packets_are_lost() {
        let rtt = Duration::from_millis(100);
        let clean = congestion_window(12_500_000, rtt, 1.0, MTU);
        let lossy = congestion_window(12_500_000, rtt, 0.8, MTU);
        // В этом весь Brutal: потери увеличивают темп, а не уменьшают его, —
        // чтобы дошедшая скорость осталась заданной.
        assert!(lossy > clean);
        assert_eq!(lossy, clean * 10 / 8);
    }

    #[test]
    fn window_has_a_floor() {
        // Окно меньше пакета остановило бы отправку насовсем.
        let window = congestion_window(1, Duration::from_micros(1), 1.0, MTU);
        assert!(window >= u64::from(MTU) * 2);
    }

    #[test]
    fn window_without_rtt_is_the_initial_one() {
        assert_eq!(
            congestion_window(12_500_000, Duration::ZERO, 1.0, MTU),
            INITIAL_WINDOW
        );
    }

    #[test]
    fn ack_rate_ignores_small_samples() {
        // Одна потеря из десяти — это не «десять процентов потерь», это шум.
        let mut tracker = RateTracker::new();
        for _ in 0..9 {
            tracker.record_ack(0);
        }
        tracker.record_loss(0);
        assert_eq!(tracker.ack_rate(), 1.0);
    }

    #[test]
    fn ack_rate_reflects_real_loss() {
        let mut tracker = RateTracker::new();
        for _ in 0..90 {
            tracker.record_ack(0);
        }
        for _ in 0..10 {
            tracker.record_loss(0);
        }
        assert!((tracker.ack_rate() - 0.9).abs() < 1e-9);
    }

    #[test]
    fn ack_rate_never_falls_below_the_floor() {
        // Полный обрыв не должен раздувать окно до бесконечности.
        let mut tracker = RateTracker::new();
        for _ in 0..100 {
            tracker.record_loss(0);
        }
        assert_eq!(tracker.ack_rate(), MIN_ACK_RATE);
    }

    #[test]
    fn old_seconds_stop_counting() {
        let mut tracker = RateTracker::new();
        for _ in 0..100 {
            tracker.record_loss(0);
        }
        assert_eq!(tracker.ack_rate(), MIN_ACK_RATE);

        // Прошло больше круга — старые потери больше не про нас.
        for _ in 0..100 {
            tracker.record_ack(10);
        }
        assert_eq!(tracker.ack_rate(), 1.0);
    }

    #[test]
    fn slot_reuse_does_not_mix_seconds() {
        // Ячеек пять; секунды 0 и 5 делят одну, и содержимое первой не должно
        // приплюсоваться ко второй.
        let mut tracker = RateTracker::new();
        for _ in 0..60 {
            tracker.record_loss(0);
        }
        for _ in 0..60 {
            tracker.record_ack(5);
        }
        assert_eq!(tracker.ack_rate(), 1.0);
    }

    #[test]
    fn bits_convert_to_bytes() {
        assert_eq!(
            BrutalConfig::from_bits_per_second(100_000_000).rate.get(),
            12_500_000
        );
    }

    #[test]
    fn controller_reports_initial_window_before_any_ack() {
        let brutal = Brutal::new(BrutalRate::from_bits_per_second(100_000_000), MTU);
        assert_eq!(brutal.window(), INITIAL_WINDOW);
        assert_eq!(brutal.initial_window(), INITIAL_WINDOW);
    }

    #[test]
    fn ecn_events_are_not_losses() {
        let mut brutal = Brutal::new(BrutalRate::from_bits_per_second(100_000_000), MTU);
        let now = Instant::now();
        for _ in 0..100 {
            brutal.on_congestion_event(now, now, false, 0);
        }
        assert_eq!(brutal.tracker.ack_rate(), 1.0);
    }
}
