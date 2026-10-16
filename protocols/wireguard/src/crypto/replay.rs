//! Скользящее окно защиты от повторов: наибольший принятый счётчик и битовая
//! карта недавних. Ширина - локальная политика приёмника.

use crate::crypto::constants::REPLAY_WINDOW_BITS;

const WORDS: usize = (REPLAY_WINDOW_BITS / 64) as usize;

/// Окно повторов одного направления приёма; на каждый сеанс новое.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Наибольший принятый счётчик.
    highest: Option<u64>,
    /// Бит `i` слова `i / 64` - принят ли `highest - i`.
    bitmap: [u64; WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            highest: None,
            bitmap: [0; WORDS],
        }
    }
}

impl ReplayWindow {
    /// Новое пустое окно.
    pub fn new() -> Self {
        Self::default()
    }

    /// Принимает счётчик, если он новый, и отмечает его.
    ///
    /// Звать только после проверки метки AEAD: иначе подделка сотрёт место настоящего.
    #[must_use]
    pub fn accept(&mut self, counter: u64) -> bool {
        match self.highest {
            None => {
                self.highest = Some(counter);
                set_bit(&mut self.bitmap, 0);
                true
            }
            Some(highest) if counter > highest => {
                let shift = counter - highest;
                if shift >= REPLAY_WINDOW_BITS {
                    self.bitmap = [0; WORDS];
                } else {
                    shift_left(&mut self.bitmap, shift);
                }
                self.highest = Some(counter);
                set_bit(&mut self.bitmap, 0);
                true
            }
            Some(highest) => {
                let age = highest - counter;
                age < REPLAY_WINDOW_BITS && !test_and_set_bit(&mut self.bitmap, age)
            }
        }
    }
}

fn set_bit(bitmap: &mut [u64; WORDS], index: u64) {
    bitmap[(index / 64) as usize] |= 1u64 << (index % 64);
}

/// Выставляет бит; возвращает, был ли он уже выставлен.
fn test_and_set_bit(bitmap: &mut [u64; WORDS], index: u64) -> bool {
    let mask = 1u64 << (index % 64);
    let word = &mut bitmap[(index / 64) as usize];
    let was_set = *word & mask != 0;
    *word |= mask;
    was_set
}

/// Сдвигает карту к старшим индексам на `amount < REPLAY_WINDOW_BITS` бит.
fn shift_left(bitmap: &mut [u64; WORDS], amount: u64) {
    debug_assert!(amount < REPLAY_WINDOW_BITS);
    let word_shift = (amount / 64) as usize;
    let bit_shift = (amount % 64) as u32;

    for i in (0..WORDS).rev() {
        let mut value = 0u64;
        if let Some(source) = i.checked_sub(word_shift) {
            value = if bit_shift == 0 {
                bitmap[source]
            } else {
                let mut v = bitmap[source] << bit_shift;
                if let Some(carry_source) = source.checked_sub(1) {
                    v |= bitmap[carry_source] >> (64 - bit_shift);
                }
                v
            };
        }
        bitmap[i] = value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_packet_of_a_session_is_accepted() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(0));
    }

    #[test]
    fn strictly_increasing_counters_are_all_accepted() {
        let mut window = ReplayWindow::new();
        for counter in 0..2000u64 {
            assert!(window.accept(counter), "{counter}");
        }
    }

    #[test]
    fn a_replayed_packet_is_refused() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(10));
        assert!(!window.accept(10), "тот же счётчик второй раз");
    }

    #[test]
    fn packets_arriving_out_of_order_within_the_window_are_accepted() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(41));
        assert!(window.accept(40));
        assert!(window.accept(39));
        assert!(!window.accept(40));
    }

    #[test]
    fn a_packet_older_than_the_window_is_refused() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(REPLAY_WINDOW_BITS + 100));
        assert!(!window.accept(50));
    }

    #[test]
    fn a_huge_jump_forward_resets_the_window_instead_of_shifting_forever() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(5));
        assert!(window.accept(REPLAY_WINDOW_BITS * 100));
        assert!(window.accept(REPLAY_WINDOW_BITS * 100 + 1));
    }

    #[test]
    fn the_oldest_counter_still_inside_the_window_is_accepted() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(REPLAY_WINDOW_BITS - 1));
        assert!(window.accept(0));
    }

    #[test]
    fn one_step_past_the_window_edge_is_refused() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(REPLAY_WINDOW_BITS));
        assert!(!window.accept(0));
    }

    #[test]
    fn shifting_forward_does_not_corrupt_unrelated_bits() {
        // Сдвиг через границу слова на не кратное 64.
        let mut window = ReplayWindow::new();
        for counter in 0..=100u64 {
            assert!(window.accept(counter));
        }
        assert!(window.accept(100 + 37));
        assert!(!window.accept(100));
        assert!(!window.accept(99));
    }
}
