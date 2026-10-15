//! Переменной длины целое QUIC (RFC 9000, §16).
//!
//! И контекст датаграммы (RFC 9298, §5), и заголовок капсулы (RFC 9297,
//! §3.2) кодируют числа этим форматом, а не фиксированной шириной. Два
//! старших бита первого байта называют длину:
//!
//! ```text
//!  биты 76543210
//!       00xxxxxx  — 1 байт,  6  бит значения
//!       01xxxxxx  — 2 байта, 14 бит значения
//!       10xxxxxx  — 4 байта, 30 бит значения
//!       11xxxxxx  — 8 байт,  62 бита значения
//! ```
//!
//! Кодирование обязано выбирать наименьшую подходящую длину (RFC 9000,
//! §16): то же число, записанное восемью байтами вместо одного, читается
//! правильно, но так сервер не делает, и сверка на чужих кадрах разошлась бы.

use bytes::{Buf, BufMut};

/// Наибольшее значение, которое влезает в 62 бита.
const MAX_VALUE: u64 = (1 << 62) - 1;

/// Дописывает `value` в `buf` в кодировке QUIC-варинта.
///
/// `value` обязано быть не больше 2^62 - 1 — оба места, что зовут эту
/// функцию (контекст датаграммы, длина и тип капсулы), сами ограничены
/// намного более тесными пределами (RFC 9298, §5: не длиннее 65527 байт).
pub fn encode(value: u64, buf: &mut impl BufMut) {
    debug_assert!(value <= MAX_VALUE, "варинт не вмещает 62 бита: {value}");

    if value <= 0x3f {
        buf.put_u8(value as u8);
    } else if value <= 0x3fff {
        buf.put_u16(0x4000 | value as u16);
    } else if value <= 0x3fff_ffff {
        buf.put_u32(0x8000_0000 | value as u32);
    } else {
        buf.put_u64(0xc000_0000_0000_0000 | value.min(MAX_VALUE));
    }
}

/// Сколько байт займёт [`encode`] для этого значения.
pub fn encoded_len(value: u64) -> usize {
    if value <= 0x3f {
        1
    } else if value <= 0x3fff {
        2
    } else if value <= 0x3fff_ffff {
        4
    } else {
        8
    }
}

/// Пытается разобрать варинт в начале `buf`.
///
/// Возвращает значение и сколько байт оно заняло. `None` — данных пока не
/// хватает; это обычное дело при чтении капсул по кускам, а не ошибка формата
/// (у варинта не бывает недопустимой первой пары бит).
pub fn try_decode(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }

    let mut value = u64::from(first & 0x3f);
    for &byte in &buf[1..len] {
        value = (value << 8) | u64::from(byte);
    }
    Some((value, len))
}

/// Читает варинт из начала `buf` и продвигает его — для уже целиком
/// известного по длине содержимого (значение капсулы), а не для потокового
/// чтения.
///
/// `None`, если байт меньше, чем нужно для заявленной длины: в
/// целиком-известном срезе это уже не «подождать ещё», а обрезанные данные.
pub fn decode_prefix(buf: &mut impl Buf) -> Option<u64> {
    let chunk = buf.chunk();
    let (value, len) = try_decode(chunk)?;
    buf.advance(len);
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Примеры из RFC 9000, §16 — единственное место в этом крейте, где есть
    // готовые тестовые векторы прямо в тексте RFC.
    const VECTORS: &[(u64, &[u8])] = &[
        (37, &[0x25]),
        (15293, &[0x7b, 0xbd]),
        (494_878_333, &[0x9d, 0x7f, 0x3e, 0x7d]),
        (
            151_288_809_941_952_652,
            &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
        ),
    ];

    #[test]
    fn the_rfc_9000_examples_round_trip() {
        for &(value, bytes) in VECTORS {
            let mut buf = Vec::new();
            encode(value, &mut buf);
            assert_eq!(buf, bytes, "кодирование {value}");
            assert_eq!(encoded_len(value), bytes.len());

            let (decoded, len) = try_decode(bytes).expect("разбирается");
            assert_eq!(decoded, value);
            assert_eq!(len, bytes.len());
        }
    }

    #[test]
    fn encoding_always_picks_the_shortest_form() {
        // 37 умещается в один байт — четыре были бы валидны для декодера, но
        // не для нас: RFC 9000 требует минимальной формы.
        let mut buf = Vec::new();
        encode(37, &mut buf);
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn a_truncated_buffer_asks_for_more_data_instead_of_erroring() {
        // Первый байт варинта на два байта — данных пока меньше.
        assert_eq!(try_decode(&[0x7b]), None);
        assert_eq!(try_decode(&[]), None);
    }

    #[test]
    fn decode_prefix_advances_the_buffer_past_the_varint() {
        let mut buf = bytes::Bytes::from_static(&[0x25, 0xaa, 0xbb]);
        let value = decode_prefix(&mut buf).expect("варинт есть");
        assert_eq!(value, 37);
        assert_eq!(&buf[..], &[0xaa, 0xbb]);
    }
}
