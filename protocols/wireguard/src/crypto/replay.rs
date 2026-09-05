//! Окно защиты от повторов: какие счётчики уже были, а какие ещё нет.
//!
//! Каждый пакет данных несёт свой собственный счётчик-нонс — он не может
//! повторяться, иначе ChaCha20-Poly1305 теряет всю стойкость. Но сеть не
//! гарантирует порядок доставки: пакет со счётчиком 41 законно может прийти
//! раньше сорокового. Принимать только строго по возрастанию значит ронять
//! на землю каждый пакет не по порядку; принимать что угодно значит принимать
//! в том числе и вредоносно посланный повторно старый пакет.
//!
//! Решение — скользящее окно: помнить наибольший принятый счётчик и битовую
//! карту недавних, и отклонять то, что либо уже отмечено, либо провалилось
//! дальше окна назад.
//!
//! Ширина окна ([`crate::crypto::constants::REPLAY_WINDOW_BITS`]) — не часть
//! договора с сервером, только локальная политика приёмника: сервер о ней не
//! знает и знать не должен.

use crate::crypto::constants::REPLAY_WINDOW_BITS;

/// Сколько 64-битных слов нужно под окно.
const WORDS: usize = (REPLAY_WINDOW_BITS / 64) as usize;

/// Окно защиты от повторов для одного направления приёма.
///
/// Новое на каждый сеанс: счётчики начинаются с нуля у каждой пары ключей,
/// и окно от предыдущего сеанса здесь неуместно.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Наибольший принятый счётчик. `None` — ещё не принято ни одного пакета.
    highest: Option<u64>,
    /// Бит `i` слова `i / 64` установлен, если счётчик `highest - i` уже
    /// принят. Бит 0 — это сам `highest`.
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

    /// Можно ли принять пакет с этим счётчиком, и если да — отмечает его как
    /// принятый.
    ///
    /// Вызывается **после** проверки метки подлинности AEAD, не раньше: до
    /// расшифровки счётчик ничем не подтверждён, и отмечать его как принятый
    /// значило бы дать чужому пакету с поддельным (но подходящим под окно)
    /// счётчиком стереть из окна место настоящего.
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
                    // Прыжок дальше всего окна: старые отметки не имеют
                    // отношения к новому месту, окно просто обнуляется.
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
                if age >= REPLAY_WINDOW_BITS {
                    // Настолько старый, что окно о нём уже ничего не помнит:
                    // мог быть, мог не быть, но пропускать его — рисковать
                    // повтором вслепую.
                    return false;
                }
                if test_and_set_bit(&mut self.bitmap, age) {
                    // Бит уже был установлен — этот счётчик тут уже проходил.
                    false
                } else {
                    true
                }
            }
        }
    }
}

/// Бит `index` внутри многословной битовой карты.
fn set_bit(bitmap: &mut [u64; WORDS], index: u64) {
    let word = (index / 64) as usize;
    let bit = index % 64;
    bitmap[word] |= 1u64 << bit;
}

/// Проверяет бит и сразу его выставляет. Возвращает, был ли он уже выставлен.
fn test_and_set_bit(bitmap: &mut [u64; WORDS], index: u64) -> bool {
    let word = (index / 64) as usize;
    let bit = index % 64;
    let mask = 1u64 << bit;
    let was_set = bitmap[word] & mask != 0;
    bitmap[word] |= mask;
    was_set
}

/// Сдвигает всю битовую карту в сторону старших индексов на `amount` бит:
/// бывший бит `i` становится битом `i + amount`. Так окно «съезжает» вперёд,
/// когда приходит пакет новее всех предыдущих, а освободившееся место у нуля
/// готово принять отметку нового `highest`.
///
/// `amount` меньше [`REPLAY_WINDOW_BITS`] — вызывающая сторона обнуляет карту
/// сама, когда сдвиг больше: сдвигать всё окно целиком в никуда бессмысленно.
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
        // Счётчики нового сеанса начинаются с нуля.
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
        // Сеть не гарантирует порядок: 41 законно может прийти раньше 40.
        let mut window = ReplayWindow::new();
        assert!(window.accept(41));
        assert!(window.accept(40));
        assert!(window.accept(39));
        // Но не оба раза одно и то же.
        assert!(!window.accept(40));
    }

    #[test]
    fn a_packet_older_than_the_window_is_refused() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(REPLAY_WINDOW_BITS + 100));
        // Всё, что вышло за пределы окна позади наибольшего, окно уже не
        // помнит — и не может отличить «был» от «не был».
        assert!(!window.accept(50));
    }

    #[test]
    fn a_huge_jump_forward_resets_the_window_instead_of_shifting_forever() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(5));
        assert!(window.accept(REPLAY_WINDOW_BITS * 100));
        // Новый счётчик принят, а старое окно не притащило с собой мусор,
        // который бы ошибочно посчитался «уже виденным».
        assert!(window.accept(REPLAY_WINDOW_BITS * 100 + 1));
    }

    #[test]
    fn the_oldest_counter_still_inside_the_window_is_accepted() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(REPLAY_WINDOW_BITS - 1));
        // Возраст ровно `REPLAY_WINDOW_BITS - 1` — последний, который окно
        // ещё помнит.
        assert!(window.accept(0));
    }

    #[test]
    fn one_step_past_the_window_edge_is_refused() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(REPLAY_WINDOW_BITS));
        // Возраст ровно `REPLAY_WINDOW_BITS` — уже за краем: окно шириной
        // `REPLAY_WINDOW_BITS` помнит только `REPLAY_WINDOW_BITS` последних
        // счётчиков, а не на один больше.
        assert!(!window.accept(0));
    }

    #[test]
    fn shifting_forward_does_not_corrupt_unrelated_bits() {
        // Регрессия на сдвиг через границу слова: 101 старый счётчик подряд
        // должен остаться различимым от новых после сдвига на не кратное 64.
        //
        // Черновик этого файла звал `0..100u64` (счётчики 0..=99, без 100) и
        // тут же проверял `!window.accept(100)` — то есть ждал повтора для
        // счётчика, которого не было в исходном наборе. Со старым циклом
        // `accept(100)` был обязан вернуть `true` (это действительно новый
        // счётчик), и тест был бы неверен независимо от `shift_left`: ловил
        // бы не регрессию сдвига, а собственную опечатку в границе.
        let mut window = ReplayWindow::new();
        for counter in 0..=100u64 {
            assert!(window.accept(counter));
        }
        assert!(window.accept(100 + 37));
        // Всё, что уже было в пределах нового окна, всё ещё числится принятым.
        assert!(!window.accept(100));
        assert!(!window.accept(99));
    }
}
