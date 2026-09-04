//! Сборка датаграмм, приехавших частями.
//!
//! Датаграмма QUIC ограничена путевым MTU, а UDP приложения — нет: DNS с
//! DNSSEC, QUIC внутри QUIC, игровой трафик легко перешагивают полторы тысячи
//! байт. Такие датаграммы едут частями и собираются здесь.
//!
//! # Два ограничения, без которых сборка становится дырой в памяти
//!
//! **Время жизни.** Части одной датаграммы уходят подряд. Не собралось за
//! несколько секунд — уже не соберётся: у UDP нет перепосылки, и ждать больше
//! нечего.
//!
//! **Потолок числа буферов.** Иначе сторона, приславшая по одной части от
//! тысячи датаграмм, занимает память под тысячу буферов и не завершает ни
//! одного.
//!
//! # Почему это здесь, а не в крейте протокола
//!
//! Дробить датаграммы приходится всем, кто носит UDP поверх QUIC: у Hysteria 2
//! это своя сессия и адрес строкой, у TUIC — номер ассоциации и разобранный
//! адрес, у Juicity будет третье. Различается только то, чем помечены части;
//! сама сборка — одна и та же, и две её копии однажды разойдутся в мелочи
//! вроде повторившегося номера пакета.
//!
//! Отсюда обобщение по типу адреса: собиратель его не разбирает и не
//! сравнивает, а просто запоминает тот, что пришёл с первой частью.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};

/// Сколько держать недособранную датаграмму.
pub const TTL: Duration = Duration::from_secs(10);

/// Сколько недособранных датаграмм помнить одновременно.
pub const MAX_PENDING: usize = 512;

/// Часть датаграммы.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment<A> {
    /// Сессия: одна на каждый канал датаграмм.
    ///
    /// Шире, чем у любого из протоколов: у Hysteria 2 она тридцатидвухбитная,
    /// у TUIC шестнадцатибитная. Общий тип избавляет от разговора о том, чей
    /// номер шире.
    pub session: u64,
    /// Номер датаграммы внутри сессии. Общий у всех её частей.
    pub packet: u16,
    /// Всего частей. Единица означает целую датаграмму.
    pub count: u8,
    /// Номер части, считая с нуля.
    pub index: u8,
    /// Адрес. При приёме — отправитель.
    pub address: A,
    /// Данные этой части.
    pub payload: Bytes,
}

impl<A> Fragment<A> {
    /// Датаграмма приехала целой.
    pub fn is_whole(&self) -> bool {
        self.count <= 1
    }
}

/// Собиратель датаграмм.
#[derive(Debug)]
pub struct Reassembler<A> {
    pending: HashMap<(u64, u16), Pending<A>>,
}

#[derive(Debug)]
struct Pending<A> {
    parts: Vec<Option<Bytes>>,
    received: u8,
    address: A,
    started: Instant,
}

impl<A> Default for Reassembler<A> {
    fn default() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }
}

impl<A: Clone> Reassembler<A> {
    /// Пустой собиратель.
    pub fn new() -> Self {
        Self::default()
    }

    /// Принимает часть.
    ///
    /// Возвращает собранную датаграмму вместе с адресом, когда она готова.
    /// Целая датаграмма проходит насквозь, ничего не занимая, — а это
    /// подавляющее большинство трафика.
    pub fn accept(&mut self, fragment: Fragment<A>) -> Option<(Bytes, A)> {
        if fragment.is_whole() {
            return Some((fragment.payload, fragment.address));
        }
        self.accept_at(fragment, Instant::now())
    }

    /// То же с явным моментом времени — для тестов, которым нельзя ждать.
    fn accept_at(&mut self, fragment: Fragment<A>, now: Instant) -> Option<(Bytes, A)> {
        // Часть с номером за пределами объявленного — это либо ошибка того
        // конца, либо попытка занять память; ни то ни другое собирать нечего.
        if fragment.index >= fragment.count {
            return None;
        }

        self.expire(now);

        let key = (fragment.session, fragment.packet);
        let count = usize::from(fragment.count);

        let entry = self.pending.entry(key).or_insert_with(|| Pending {
            parts: vec![None; count],
            received: 0,
            address: fragment.address.clone(),
            started: now,
        });

        // Номер пакета шестнадцатибитный и рано или поздно повторится. Часть
        // от другой датаграммы с тем же номером — не повод склеить их вместе.
        if entry.parts.len() != count {
            *entry = Pending {
                parts: vec![None; count],
                received: 0,
                address: fragment.address.clone(),
                started: now,
            };
        }

        let slot = entry.parts.get_mut(usize::from(fragment.index))?;
        if slot.is_none() {
            *slot = Some(fragment.payload);
            entry.received += 1;
        }

        if usize::from(entry.received) < count {
            return None;
        }

        let entry = self.pending.remove(&key)?;
        let total: usize = entry.parts.iter().flatten().map(Bytes::len).sum();
        let mut joined = BytesMut::with_capacity(total);
        for part in entry.parts.into_iter().flatten() {
            joined.extend_from_slice(&part);
        }
        Some((joined.freeze(), entry.address))
    }

    /// Сколько датаграмм ждут сборки. Для диагностики и тестов.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Выбрасывает то, чего уже не дождаться, и держит потолок.
    fn expire(&mut self, now: Instant) {
        self.pending
            .retain(|_, entry| now.duration_since(entry.started) < TTL);

        while self.pending.len() >= MAX_PENDING {
            let Some(oldest) = self
                .pending
                .iter()
                .min_by_key(|(_, entry)| entry.started)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.pending.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Часть датаграммы с адресом-строкой.
    fn part(packet: u16, count: u8, index: u8, payload: &[u8]) -> Fragment<&'static str> {
        Fragment {
            session: 1,
            packet,
            count,
            index,
            address: "1.2.3.4:53",
            payload: Bytes::copy_from_slice(payload),
        }
    }

    #[test]
    fn a_whole_datagram_passes_through_without_buffering() {
        // Подавляющее большинство трафика — целые датаграммы: платить за них
        // записью в таблицу незачем.
        let mut reassembler = Reassembler::new();
        let (payload, address) = reassembler
            .accept(part(7, 1, 0, b"payload"))
            .expect("готова сразу");

        assert_eq!(&payload[..], b"payload");
        assert_eq!(address, "1.2.3.4:53");
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn parts_are_joined_in_order_whatever_order_they_arrive() {
        // У UDP порядка нет: части приезжают как придётся, а склеиться обязаны
        // по своим номерам.
        let mut reassembler = Reassembler::new();
        assert!(reassembler.accept(part(7, 3, 2, b"three")).is_none());
        assert!(reassembler.accept(part(7, 3, 0, b"one")).is_none());

        let (payload, _) = reassembler
            .accept(part(7, 3, 1, b"two"))
            .expect("собралась");
        assert_eq!(&payload[..], b"onetwothree");
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn a_repeated_part_does_not_count_twice() {
        // Иначе датаграмма «соберётся» из двух копий одной части.
        let mut reassembler = Reassembler::new();
        assert!(reassembler.accept(part(7, 2, 0, b"one")).is_none());
        assert!(reassembler.accept(part(7, 2, 0, b"one")).is_none());

        let (payload, _) = reassembler
            .accept(part(7, 2, 1, b"two"))
            .expect("собралась");
        assert_eq!(&payload[..], b"onetwo");
    }

    #[test]
    fn a_part_beyond_the_announced_count_is_dropped() {
        let mut reassembler = Reassembler::new();
        assert!(reassembler.accept(part(7, 2, 5, b"beyond")).is_none());
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn a_reused_packet_number_starts_over() {
        // Номер шестнадцатибитный и повторяется; склеить части двух разных
        // датаграмм — значит отдать приложению мусор.
        let mut reassembler = Reassembler::new();
        assert!(reassembler.accept(part(7, 3, 0, b"one")).is_none());

        // Тот же номер, но частей теперь две — это уже другая датаграмма.
        assert!(reassembler.accept(part(7, 2, 0, b"a")).is_none());
        let (payload, _) = reassembler.accept(part(7, 2, 1, b"b")).expect("собралась");
        assert_eq!(&payload[..], b"ab");
    }

    #[test]
    fn different_sessions_do_not_mix() {
        let mut reassembler = Reassembler::new();
        let mut other = part(7, 2, 0, b"other");
        other.session = 2;

        assert!(reassembler.accept(part(7, 2, 0, b"one")).is_none());
        assert!(reassembler.accept(other).is_none());
        assert_eq!(reassembler.pending_count(), 2, "сессии слиплись");
    }

    #[test]
    fn what_never_arrives_is_forgotten() {
        // У UDP нет перепосылки: не собралось за отведённое время — не
        // соберётся никогда, и держать буфер незачем.
        let mut reassembler = Reassembler::new();
        let start = Instant::now();
        assert!(
            reassembler
                .accept_at(part(7, 2, 0, b"one"), start)
                .is_none()
        );
        assert_eq!(reassembler.pending_count(), 1);

        let later = start + TTL + Duration::from_secs(1);
        assert!(
            reassembler
                .accept_at(part(8, 2, 0, b"another"), later)
                .is_none()
        );
        assert_eq!(reassembler.pending_count(), 1, "старое не выброшено");
    }

    #[test]
    fn the_number_of_buffers_has_a_ceiling() {
        // Сторона, приславшая по одной части от тысячи датаграмм, иначе
        // занимает память под тысячу буферов и не завершает ни одного.
        let mut reassembler = Reassembler::new();
        let start = Instant::now();

        for packet in 0..u16::try_from(MAX_PENDING + 100).unwrap_or(u16::MAX) {
            let moment = start + Duration::from_millis(u64::from(packet));
            reassembler.accept_at(part(packet, 2, 0, b"piece"), moment);
        }
        assert!(
            reassembler.pending_count() <= MAX_PENDING,
            "потолок не держится: {}",
            reassembler.pending_count()
        );
    }
}
