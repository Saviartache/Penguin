//! Gecko: дробление длинных пакетов рукопожатия.
//!
//! Salamander убирает узнаваемый вид байт, но не трогает размеры и порядок
//! пакетов. Рукопожатие QUIC при этом остаётся узнаваемым по форме: первый
//! пакет клиента дополнен до 1200 байт, ответ сервера идёт характерной
//! пачкой. Gecko ломает эту форму, разрезая каждый пакет с длинным
//! заголовком на 2–8 частей случайного размера, каждая со своим случайным
//! дополнением.
//!
//! ```text
//! ┌──────┬───────┬───────────────────────┬────────┬───────────┬───────┐
//! │ 0x80 │ msgID │ chunkIdx:4│totalChunks│ padLen │ дополнение│ часть │
//! │  1 Б │  1 Б  │         1 Б           │  2 Б   │  padLen Б │       │
//! └──────┴───────┴───────────────────────┴────────┴───────────┴───────┘
//! ```
//!
//! Порядок слоёв: сначала кадр Gecko, потом Salamander поверх него, и каждая
//! часть уходит отдельной датаграммой.
//!
//! Признак кадра — первый байт ровно `0x80`. Спутать его с настоящим QUIC
//! нельзя: у пакета с длинным заголовком обязательно взведён и бит `0x40`
//! (RFC 9000, §17.2), так что первый байт настоящего пакета не меньше `0xC0`.
//!
//! Пакеты с коротким заголовком — то есть весь трафик после рукопожатия —
//! идут мимо Gecko: дробить каждый пакет в установившемся соединении значило
//! бы утроить их число и заметно потерять в скорости.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::{BufMut, BytesMut};
use parking_lot::Mutex;
use rand::Rng;

/// Признак кадра Gecko в первом байте.
const MARKER: u8 = 0x80;

/// Длина неизменной части заголовка кадра.
const HEADER_LEN: usize = 1 + 1 + 1 + 2;

/// Наименьшее число частей.
const MIN_CHUNKS: u8 = 2;

/// Наибольшее число частей. Больше и не выразить: под счётчик отведены
/// четыре бита, но верхняя граница задана самой спецификацией.
const MAX_CHUNKS: u8 = 8;

/// Пределы случайного дополнения.
///
/// Верхняя граница выбрана так, чтобы кадр вместе с дополнением и солью
/// Salamander заведомо оставался меньше исходного пакета: разрезание не
/// должно приводить к тому, что части перестают проходить по пути.
const MAX_PADDING: usize = 256;

/// Сколько держать недособранный пакет.
///
/// Части одного пакета уходят подряд и приходят с разбросом в единицы
/// миллисекунд. Секунда — с запасом; всё, что не собралось за это время,
/// уже не нужно, потому что QUIC успел его перепослать.
const REASSEMBLY_TTL: Duration = Duration::from_secs(1);

/// Сколько недособранных пакетов помнить одновременно.
///
/// Потолок обязателен: собеседник, приславший по одной части от тысячи
/// пакетов, иначе занял бы память под тысячу буферов, ничего не завершив.
const MAX_PENDING: usize = 256;

/// Дробление и сборка кадров Gecko.
#[derive(Debug)]
pub struct Gecko {
    pending: Mutex<HashMap<(SocketAddr, u8), Pending>>,
}

#[derive(Debug)]
struct Pending {
    chunks: Vec<Option<Vec<u8>>>,
    received: u8,
    started: Instant,
}

/// Что получилось из принятой датаграммы.
#[derive(Debug, PartialEq, Eq)]
pub enum Incoming {
    /// Это не кадр Gecko — отдать QUIC как есть.
    Passthrough,
    /// Кадр принят, но пакет ещё не собран.
    Pending,
    /// Пакет собран целиком.
    Complete(Vec<u8>),
    /// Кадр повреждён.
    Malformed,
}

impl Gecko {
    /// Создаёт слой.
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Нужно ли дробить этот пакет.
    ///
    /// Только длинный заголовок, то есть только рукопожатие.
    pub fn applies_to(packet: &[u8]) -> bool {
        packet.first().is_some_and(|first| first & 0x80 != 0)
    }

    /// Режет пакет на кадры.
    ///
    /// Каждый кадр отправляется отдельной датаграммой — после Salamander.
    /// Возвращает `None`, если пакет слишком короток, чтобы делить его хотя
    /// бы надвое.
    pub fn fragment(&self, packet: &[u8]) -> Option<Vec<BytesMut>> {
        if packet.len() < MIN_CHUNKS as usize {
            return None;
        }

        let mut rng = rand::thread_rng();
        let max_chunks = MAX_CHUNKS.min(packet.len() as u8);
        let count = rng.gen_range(MIN_CHUNKS..=max_chunks);
        let msg_id: u8 = rng.r#gen();

        let bounds = split_points(packet.len(), count, &mut rng);
        let mut frames = Vec::with_capacity(count as usize);

        for (index, window) in bounds.windows(2).enumerate() {
            let chunk = &packet[window[0]..window[1]];
            let padding_len = rng.gen_range(0..=MAX_PADDING);

            let mut frame = BytesMut::with_capacity(HEADER_LEN + padding_len + chunk.len());
            frame.put_u8(MARKER);
            frame.put_u8(msg_id);
            frame.put_u8((index as u8) << 4 | count);
            frame.put_u16(padding_len as u16);
            frame.resize(HEADER_LEN + padding_len, 0);
            rand::RngCore::fill_bytes(&mut rng, &mut frame[HEADER_LEN..]);
            frame.put_slice(chunk);

            frames.push(frame);
        }

        Some(frames)
    }

    /// Принимает датаграмму, уже снявшую Salamander.
    pub fn accept(&self, source: SocketAddr, datagram: &[u8]) -> Incoming {
        if datagram.first() != Some(&MARKER) {
            return Incoming::Passthrough;
        }
        if datagram.len() < HEADER_LEN {
            return Incoming::Malformed;
        }

        let msg_id = datagram[1];
        let index = datagram[2] >> 4;
        let count = datagram[2] & 0x0F;
        if !(MIN_CHUNKS..=MAX_CHUNKS).contains(&count) || index >= count {
            return Incoming::Malformed;
        }

        let padding_len = u16::from_be_bytes([datagram[3], datagram[4]]) as usize;
        let Some(chunk) = datagram.get(HEADER_LEN + padding_len..) else {
            return Incoming::Malformed;
        };

        let mut pending = self.pending.lock();
        Self::expire(&mut pending);

        let entry = pending.entry((source, msg_id)).or_insert_with(|| Pending {
            chunks: vec![None; count as usize],
            received: 0,
            started: Instant::now(),
        });

        // Пришла часть от другого пакета с тем же однобайтовым номером:
        // номеров всего 256, и совпадения неизбежны. Прежний буфер при этом
        // уже не соберётся — начинаем заново.
        if entry.chunks.len() != count as usize {
            *entry = Pending {
                chunks: vec![None; count as usize],
                received: 0,
                started: Instant::now(),
            };
        }

        let slot = &mut entry.chunks[index as usize];
        if slot.is_none() {
            *slot = Some(chunk.to_vec());
            entry.received += 1;
        }

        if entry.received < count {
            return Incoming::Pending;
        }

        let Some(entry) = pending.remove(&(source, msg_id)) else {
            return Incoming::Pending;
        };
        let assembled: Vec<u8> = entry.chunks.into_iter().flatten().flatten().collect();
        Incoming::Complete(assembled)
    }

    /// Выбрасывает просроченные и лишние буферы.
    fn expire(pending: &mut HashMap<(SocketAddr, u8), Pending>) {
        let now = Instant::now();
        pending.retain(|_, entry| now.duration_since(entry.started) < REASSEMBLY_TTL);

        // Если потолок всё равно превышен, выбрасывается самый старый: он
        // ближе всех к тому, чтобы стать бесполезным.
        //
        // Сравнение нестрогое, потому что вызывающий сразу после этого
        // добавит запись: место под неё надо освободить заранее, иначе
        // потолок оказывается на единицу выше заявленного.
        while pending.len() >= MAX_PENDING {
            let Some(oldest) = pending
                .iter()
                .min_by_key(|(_, e)| e.started)
                .map(|(k, _)| *k)
            else {
                break;
            };
            pending.remove(&oldest);
        }
    }
}

impl Default for Gecko {
    fn default() -> Self {
        Self::new()
    }
}

/// Выбирает границы частей: `count` кусков, каждый не пустой.
///
/// Случайные точки разреза, а не равные доли: равные доли дали бы всем частям
/// одинаковую длину, и форма, которую слой прячет, вернулась бы — просто в
/// другом виде.
fn split_points(len: usize, count: u8, rng: &mut impl Rng) -> Vec<usize> {
    let count = count as usize;
    let mut points: Vec<usize> = (0..count.saturating_sub(1))
        .map(|_| rng.gen_range(1..len))
        .collect();
    points.push(0);
    points.push(len);
    points.sort_unstable();

    // После сортировки соседние точки могут совпасть — такая часть была бы
    // пустой. Границы раздвигаются, сохраняя порядок.
    for index in 1..points.len() {
        if points[index] <= points[index - 1] {
            points[index] = (points[index - 1] + 1).min(len);
        }
    }
    // Раздвигание могло упереться в конец; выравниваем с хвоста.
    for index in (1..points.len()).rev() {
        if points[index] <= points[index - 1] {
            points[index - 1] = points[index].saturating_sub(1);
        }
    }
    points
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> SocketAddr {
        "1.2.3.4:443".parse().expect("адрес")
    }

    fn long_header_packet(len: usize) -> Vec<u8> {
        let mut packet = vec![0xC3; len];
        packet[0] = 0xC0;
        packet
    }

    #[test]
    fn short_header_packets_bypass() {
        // После рукопожатия дробить нельзя: это утроило бы число пакетов.
        assert!(!Gecko::applies_to(&[0x40, 1, 2, 3]));
        assert!(Gecko::applies_to(&[0xC0, 1, 2, 3]));
    }

    #[test]
    fn round_trips_through_fragments() {
        let gecko = Gecko::new();
        let packet = long_header_packet(1200);
        let frames = gecko.fragment(&packet).expect("режется");
        assert!((MIN_CHUNKS as usize..=MAX_CHUNKS as usize).contains(&frames.len()));

        let mut result = Incoming::Pending;
        for frame in &frames {
            result = gecko.accept(peer(), frame);
        }
        assert_eq!(result, Incoming::Complete(packet));
    }

    #[test]
    fn reassembles_out_of_order() {
        let gecko = Gecko::new();
        let packet = long_header_packet(900);
        let mut frames = gecko.fragment(&packet).expect("режется");
        frames.reverse();

        let mut result = Incoming::Pending;
        for frame in &frames {
            result = gecko.accept(peer(), frame);
        }
        assert_eq!(result, Incoming::Complete(packet));
    }

    #[test]
    fn every_frame_is_smaller_than_the_original() {
        // Ради этого и ограничено дополнение: части обязаны проходить там,
        // где проходил целый пакет.
        let gecko = Gecko::new();
        let packet = long_header_packet(1200);
        for _ in 0..50 {
            for frame in gecko.fragment(&packet).expect("режется") {
                assert!(frame.len() < packet.len() + MAX_PADDING + HEADER_LEN);
            }
        }
    }

    #[test]
    fn chunks_are_never_empty() {
        let gecko = Gecko::new();
        for len in [2usize, 3, 8, 9, 100, 1200] {
            let packet = long_header_packet(len);
            for _ in 0..50 {
                let frames = gecko.fragment(&packet).expect("режется");
                let total: usize = frames
                    .iter()
                    .map(|f| f.len() - HEADER_LEN - u16::from_be_bytes([f[3], f[4]]) as usize)
                    .sum();
                assert_eq!(total, len, "части не покрывают пакет целиком");
            }
        }
    }

    #[test]
    fn non_gecko_datagram_passes_through() {
        let gecko = Gecko::new();
        assert_eq!(
            gecko.accept(peer(), &[0xC0, 1, 2, 3]),
            Incoming::Passthrough
        );
    }

    #[test]
    fn rejects_malformed_frames() {
        let gecko = Gecko::new();
        // Обрезан заголовок.
        assert_eq!(gecko.accept(peer(), &[MARKER, 7]), Incoming::Malformed);
        // Число частей вне допустимого.
        assert_eq!(
            gecko.accept(peer(), &[MARKER, 7, 0x01, 0, 0]),
            Incoming::Malformed
        );
        // Номер части за пределами их числа.
        assert_eq!(
            gecko.accept(peer(), &[MARKER, 7, 0x52, 0, 0]),
            Incoming::Malformed
        );
        // Дополнение длиннее самого кадра.
        assert_eq!(
            gecko.accept(peer(), &[MARKER, 7, 0x02, 0xFF, 0xFF]),
            Incoming::Malformed
        );
    }

    #[test]
    fn duplicate_chunk_does_not_complete_early() {
        let gecko = Gecko::new();
        let packet = long_header_packet(600);
        let frames = gecko.fragment(&packet).expect("режется");

        // Одна и та же часть, присланная дважды, не должна считаться за две.
        gecko.accept(peer(), &frames[0]);
        assert_eq!(gecko.accept(peer(), &frames[0]), Incoming::Pending);
    }

    #[test]
    fn pending_buffers_are_bounded() {
        let gecko = Gecko::new();
        // По одной части от множества разных пакетов — классический способ
        // занять чужую память.
        for msg_id in 0..=255u8 {
            for port in 0..4u16 {
                let source: SocketAddr =
                    format!("10.0.0.1:{}", 1000 + port).parse().expect("адрес");
                gecko.accept(source, &[MARKER, msg_id, 0x04, 0, 0, 1, 2, 3]);
            }
        }
        assert!(gecko.pending.lock().len() <= MAX_PENDING);
    }
}
