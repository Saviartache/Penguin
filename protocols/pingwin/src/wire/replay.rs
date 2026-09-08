//! Окно повторов: почему одно и то же приветствие нельзя проиграть дважды.
//!
//! # Зачем это нужно именно здесь
//!
//! У 0-RTT есть врождённая беда: ранние данные едут до того, как стороны
//! обменялись хоть чем-нибудь свежим, и потому их можно записать и послать
//! ещё раз. TLS 1.3 с этим живёт и честно предупреждает: за отсутствие
//! повторов отвечает приложение.
//!
//! Здесь повтор закрывается полностью, и стоит это одной таблицы:
//!
//! - **отметка времени** в данных опознания отсекает всё, что старше окна;
//! - **эфемерный ключ клиента** (тридцать два байта, свои на каждое
//!   соединение) запоминается на длину окна и второй раз не принимается.
//!
//! Вместе они не оставляют щели: повтор внутри окна ловится таблицей, повтор
//! после окна — отметкой времени.
//!
//! # Про часы
//!
//! Окно — это ещё и требование к часам обеих сторон. Разъехавшиеся на пять
//! минут часы клиента означают отказ на каждом соединении, и сообщение об
//! этом должно называть причину, а не «сервер молчит». Поэтому окно широкое:
//! две минуты в каждую сторону.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Насколько отметка времени клиента может разойтись с часами сервера.
///
/// Две минуты в каждую сторону: столько набегает у машины без синхронизации
/// часов за несколько дней, и отвергать её было бы отказом из-за чужой
/// настройки. Шире делать нельзя: окно — это ещё и объём таблицы повторов.
pub const WINDOW: Duration = Duration::from_secs(120);

/// Секунды с начала эпохи.
///
/// Ноль, если часы стоят раньше эпохи: паниковать здесь нельзя, а отметка
/// времени из тридцатых годов прошлого века всё равно не пройдёт проверку.
pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Таблица уже виденных приветствий.
#[derive(Debug)]
pub struct ReplayWindow {
    window: u64,
    seen: HashMap<[u8; 32], u64>,
}

impl ReplayWindow {
    /// Пустое окно шириной `window`.
    pub fn new(window: Duration) -> Self {
        Self {
            window: window.as_secs().max(1),
            seen: HashMap::new(),
        }
    }

    /// Укладывается ли отметка времени клиента в окно.
    pub fn time_is_fresh(&self, stamp: u64, now: u64) -> bool {
        now.abs_diff(stamp) <= self.window
    }

    /// Принимает эфемерный ключ клиента.
    ///
    /// `false` — такой ключ уже был: это повтор, и обслуживать его нельзя.
    /// Заодно чистит всё, что старше окна, — отдельной уборки не нужно, а
    /// расти таблице некуда: в ней живёт ровно то, что пришло за окно.
    pub fn admit(&mut self, key: [u8; 32], now: u64) -> bool {
        let window = self.window;
        self.seen
            .retain(|_, seen_at| now.saturating_sub(*seen_at) <= window);
        self.seen.insert(key, now).is_none()
    }

    /// Сколько приветствий помнится сейчас.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Окно пусто.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new(WINDOW)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_hello_is_admitted_once_and_only_once() {
        // Ради этого окно и заведено: повтор ранних данных иначе означал бы
        // повторный запрос к тому же адресу с тем же телом.
        let mut window = ReplayWindow::default();
        assert!(window.admit([1u8; 32], 1000));
        assert!(!window.admit([1u8; 32], 1000));
        assert!(!window.admit([1u8; 32], 1060), "повтор внутри окна прошёл");
    }

    #[test]
    fn different_hellos_do_not_shadow_each_other() {
        let mut window = ReplayWindow::default();
        assert!(window.admit([1u8; 32], 1000));
        assert!(window.admit([2u8; 32], 1000));
        assert_eq!(window.len(), 2);
    }

    #[test]
    fn the_table_forgets_what_the_timestamp_would_reject_anyway() {
        // Расти таблице некуда: за окном приветствие всё равно не примут по
        // отметке времени, и держать его дальше значит копить память.
        let mut window = ReplayWindow::new(Duration::from_secs(10));
        assert!(window.admit([1u8; 32], 1000));
        assert!(window.admit([2u8; 32], 1100));
        assert_eq!(window.len(), 1, "старое не забылось");
        assert!(window.admit([1u8; 32], 1100), "старое не освободило места");
    }

    #[test]
    fn a_stale_timestamp_is_refused_in_both_directions() {
        // И отставшие часы клиента, и убежавшие вперёд — одинаковая беда, и
        // ответ на неё один.
        let window = ReplayWindow::new(Duration::from_secs(120));
        assert!(window.time_is_fresh(1000, 1000));
        assert!(window.time_is_fresh(1000, 1120));
        assert!(window.time_is_fresh(1120, 1000));
        assert!(!window.time_is_fresh(1000, 1121));
        assert!(!window.time_is_fresh(1121, 1000));
    }

    #[test]
    fn a_zero_window_does_not_divide_the_world_by_zero() {
        // Настройка «ноль секунд» законна на вид и означала бы окно, в
        // которое не попадает ничего, включая свежее приветствие.
        let window = ReplayWindow::new(Duration::ZERO);
        assert!(window.time_is_fresh(1000, 1000));
        assert!(window.time_is_fresh(1000, 1001));
    }

    #[test]
    fn the_clock_moves_forward() {
        assert!(now_seconds() > 1_700_000_000, "часы стоят до 2023 года");
    }
}
