//! Сборка фрагментированных датаграмм с временем жизни.
//!
//! Датаграмма QUIC ограничена путевым MTU, а UDP приложения — нет: DNS с
//! DNSSEC, QUIC внутри QUIC, игровой трафик легко перешагивают полторы
//! тысячи байт. Такие датаграммы едут частями и собираются здесь.
//!
//! Два ограничения, без которых сборка становится дырой в памяти:
//!
//! - **время жизни.** Части одной датаграммы уходят подряд. Не собралось за
//!   несколько секунд — уже не соберётся: у UDP нет перепосылки, и ждать
//!   больше нечего.
//! - **потолок числа буферов.** Иначе сторона, приславшая по одной части от
//!   тысячи датаграмм, занимает память под тысячу буферов и не завершает ни
//!   одного.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};

use crate::frame::udp::UdpMessage;

/// Сколько держать недособранную датаграмму.
const TTL: Duration = Duration::from_secs(10);

/// Сколько недособранных датаграмм помнить одновременно.
const MAX_PENDING: usize = 512;

/// Ключ буфера: сессия и номер пакета.
type Key = (u32, u16);

/// Собиратель фрагментированных датаграмм.
#[derive(Debug, Default)]
pub struct Reassembler {
    pending: HashMap<Key, Pending>,
}

#[derive(Debug)]
struct Pending {
    parts: Vec<Option<Bytes>>,
    received: u8,
    address: String,
    started: Instant,
}

impl Reassembler {
    /// Пустой собиратель.
    pub fn new() -> Self {
        Self::default()
    }

    /// Принимает сообщение.
    ///
    /// Возвращает собранную датаграмму вместе с адресом, когда она готова.
    /// Целая датаграмма проходит насквозь, ничего не занимая, — а это
    /// подавляющее большинство трафика.
    pub fn accept(&mut self, message: UdpMessage) -> Option<(Bytes, String)> {
        if message.is_whole() {
            return Some((message.payload, message.address));
        }
        self.accept_at(message, Instant::now())
    }

    /// То же с явным моментом времени — для тестов, которым нельзя ждать.
    fn accept_at(&mut self, message: UdpMessage, now: Instant) -> Option<(Bytes, String)> {
        if message.fragment_id >= message.fragment_count {
            return None;
        }

        self.expire(now);

        let key = (message.session_id, message.packet_id);
        let count = message.fragment_count as usize;

        let entry = self.pending.entry(key).or_insert_with(|| Pending {
            parts: vec![None; count],
            received: 0,
            address: message.address.clone(),
            started: now,
        });

        // Номер пакета шестнадцатибитный и рано или поздно повторится. Часть
        // от другой датаграммы с тем же номером — не повод склеить их вместе.
        if entry.parts.len() != count {
            *entry = Pending {
                parts: vec![None; count],
                received: 0,
                address: message.address.clone(),
                started: now,
            };
        }

        let slot = &mut entry.parts[message.fragment_id as usize];
        if slot.is_none() {
            *slot = Some(message.payload);
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

    fn expire(&mut self, now: Instant) {
        self.pending
            .retain(|_, entry| now.duration_since(entry.started) < TTL);

        while self.pending.len() >= MAX_PENDING {
            let Some(oldest) = self
                .pending
                .iter()
                .min_by_key(|(_, e)| e.started)
                .map(|(k, _)| *k)
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
    use crate::frame::udp;

    fn parts(payload: &[u8], max_datagram: usize) -> Vec<UdpMessage> {
        udp::fragment(
            1,
            7,
            "1.2.3.4:53",
            Bytes::copy_from_slice(payload),
            max_datagram,
        )
        .expect("режется")
    }

    #[test]
    fn whole_datagram_passes_through_without_buffering() {
        let mut reassembler = Reassembler::new();
        let message = parts(b"short", 1200).remove(0);
        let (payload, address) = reassembler.accept(message).expect("готово сразу");
        assert_eq!(&payload[..], b"short");
        assert_eq!(address, "1.2.3.4:53");
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn reassembles_in_order() {
        let payload = vec![9u8; 3000];
        let mut reassembler = Reassembler::new();
        let mut result = None;
        for part in parts(&payload, 1200) {
            result = reassembler.accept(part);
        }
        let (joined, _) = result.expect("собралось");
        assert_eq!(joined.to_vec(), payload);
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn reassembles_out_of_order() {
        let payload = vec![3u8; 5000];
        let mut pieces = parts(&payload, 1200);
        pieces.reverse();

        let mut reassembler = Reassembler::new();
        let mut result = None;
        for part in pieces {
            result = reassembler.accept(part);
        }
        assert_eq!(result.expect("собралось").0.to_vec(), payload);
    }

    #[test]
    fn incomplete_datagram_expires() {
        let payload = vec![1u8; 3000];
        let mut pieces = parts(&payload, 1200);
        let mut reassembler = Reassembler::new();

        let start = Instant::now();
        assert!(reassembler.accept_at(pieces.remove(0), start).is_none());
        assert_eq!(reassembler.pending_count(), 1);

        // Прошло больше времени жизни — буфер выброшен, потому что остальные
        // части уже не придут: перепосылки у UDP нет.
        let later = start + TTL + Duration::from_secs(1);
        let last = pieces.pop().expect("есть ещё части");
        reassembler.accept_at(last, later);
        assert_eq!(reassembler.pending_count(), 1, "остался только новый буфер");
    }

    #[test]
    fn duplicate_fragment_does_not_complete_early() {
        let payload = vec![5u8; 3000];
        let pieces = parts(&payload, 1200);
        let mut reassembler = Reassembler::new();

        reassembler.accept(pieces[0].clone());
        // Тот же фрагмент второй раз — это не второй фрагмент.
        assert!(reassembler.accept(pieces[0].clone()).is_none());
    }

    #[test]
    fn rejects_fragment_index_out_of_range() {
        let mut reassembler = Reassembler::new();
        let broken = UdpMessage {
            session_id: 1,
            packet_id: 1,
            fragment_id: 5,
            fragment_count: 3,
            address: "1.2.3.4:53".to_owned(),
            payload: Bytes::from_static(b"x"),
        };
        assert!(reassembler.accept(broken).is_none());
        assert_eq!(reassembler.pending_count(), 0);
    }

    #[test]
    fn pending_buffers_are_bounded() {
        let mut reassembler = Reassembler::new();
        let now = Instant::now();
        for packet_id in 0..2000u16 {
            let piece = UdpMessage {
                session_id: 1,
                packet_id,
                fragment_id: 0,
                fragment_count: 4,
                address: "1.2.3.4:53".to_owned(),
                payload: Bytes::from_static(b"x"),
            };
            reassembler.accept_at(piece, now);
        }
        assert!(reassembler.pending_count() <= MAX_PENDING);
    }
}
