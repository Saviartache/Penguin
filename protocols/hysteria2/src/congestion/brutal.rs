//! Brutal: заданная скорость вместо реакции на потери. Реализация трейта
//! `Controller` из quinn.
//!
//! Обычное управление перегрузкой считает потерю признаком затора и сбрасывает
//! скорость. На канале, где потери берутся не от затора, а от самой линии —
//! или от того, кто в неё вмешивается, — это разрушительно: несколько
//! процентов потерь роняют скорость в разы, и восстановиться она не успевает.
//!
//! Brutal исходит из того, что скорость канала известна заранее: её называет
//! пользователь. Потери не уменьшают темп, а увеличивают его — ровно настолько,
//! чтобы **дошедшая** скорость осталась той, что задана. Отсюда `ack_rate`:
//! доля дошедших пакетов, на которую делится окно.
//!
//! Обратная сторона очевидна и упомянута в настройках: завышенное число
//! означает, что клиент забивает канал, до которого ему нет дела, и получает
//! задержки вместо скорости.
//!
//! # Отличие от эталонной реализации
//!
//! В Go у Brutal собственный пейсер, отмеряющий ровно `bps / ack_rate` байт в
//! секунду, а окно берётся с двукратным запасом (`bps · rtt · 2`) — так, чтобы
//! ограничивал темп именно пейсер, а окно ему не мешало.
//!
//! В quinn пейсера, независимого от окна, нет: он пополняет корзину со
//! скоростью `окно · 1.25 / rtt`. При двукратном окне это дало бы вдвое
//! больший темп, чем просил пользователь. Поэтому множитель здесь единица:
//! ограничивать начинает окно, и установившаяся скорость равна `окно / rtt`,
//! то есть в точности `bps / ack_rate`. Пейсер при этом остаётся на четверть
//! быстрее и продолжает делать своё дело — сглаживать всплески.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerFactory};
use quinn_proto::RttEstimator;

/// Сколько односекундных отсчётов помнить.
const SLOT_COUNT: u64 = 5;

/// Сколько пакетов надо увидеть, чтобы доля дошедших что-то значила.
///
/// На десятке пакетов одна потеря даёт «десять процентов потерь», и окно
/// подскочило бы на ровном месте.
const MIN_SAMPLES: u64 = 50;

/// Ниже этой доли не опускаемся.
///
/// Иначе при полном обрыве `ack_rate` уходит к нулю, окно — к бесконечности,
/// и клиент начинает молотить в мёртвый канал со всей силы.
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

/// Доля дошедших пакетов за последние несколько секунд.
///
/// Сколько именно — задаёт `SLOT_COUNT`, и наружу это число не выносится:
/// длина окна — внутреннее дело оценщика.
///
/// Отдельная структура без единого обращения к сети и часам: вся арифметика
/// Brutal проверяется тестами, не поднимая соединения.
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

    /// Отсчёт под указанную секунду, с обнулением протухшего.
    ///
    /// Кольцо из пяти ячеек: секунда попадает в ячейку по остатку, и если там
    /// лежит другая секунда — значит, отсчёт устарел ровно на круг и его
    /// содержимое больше не про нас.
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
///
/// Свободная функция: окно — чистая арифметика от четырёх чисел, и проверять
/// её удобнее отдельно от соединения.
pub fn congestion_window(bytes_per_second: u64, rtt: Duration, ack_rate: f64, mtu: u16) -> u64 {
    if rtt.is_zero() || bytes_per_second == 0 {
        return INITIAL_WINDOW;
    }
    let rate = ack_rate.max(MIN_ACK_RATE);
    let window = bytes_per_second as f64 * rtt.as_secs_f64() / rate;

    // Пол в два кадра: окно меньше пакета останавливает отправку совсем, и
    // соединение умирает от собственного управления перегрузкой.
    let floor = u64::from(mtu) * 2;
    (window as u64).max(floor)
}

/// Скорость, которую держит Brutal, — разделяемая и изменяемая на ходу.
///
/// Изменяемость здесь не роскошь. Настоящий предел выясняется только после
/// аутентификации: сервер называет свою скорость приёма в заголовке
/// `Hysteria-CC-RX`, и слать быстрее неё бессмысленно. А поменять управление
/// перегрузкой у живого соединения quinn не даёт — оно задаётся один раз, при
/// подключении.
///
/// Поэтому меняется не управление, а число внутри него: контроллер читает
/// скорость на каждом вычислении окна и подхватывает новое значение сам.
#[derive(Debug, Clone)]
pub struct BrutalRate(Arc<AtomicU64>);

impl BrutalRate {
    /// Из скорости в **байтах** в секунду.
    ///
    /// Именно в байтах: в этих же единицах скорость едет в заголовке
    /// `Hysteria-CC-RX`, и разнобой здесь означал бы, что сервер и клиент
    /// договариваются о разных числах.
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

    /// Опускает скорость до указанной, если та ниже.
    ///
    /// Ровно то, что делает ответ сервера: он не назначает скорость, а
    /// ограничивает её сверху. Ноль в ответе означает «без ограничений» и
    /// разбирается вызывающим, сюда не доходит.
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

    /// Номер секунды с начала соединения.
    ///
    /// Своя точка отсчёта, а не системные часы: перевод часов не должен
    /// обнулять статистику посреди работы.
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
        // `conservative` — максимум из сглаженной и последней задержки, как
        // и в эталонной реализации. Заниженная задержка здесь опаснее
        // завышенной: она сжимает окно и режет скорость.
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
        // События приходят и от ECN, где потерянных байт нет. Потерей
        // считается только настоящая потеря.
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
