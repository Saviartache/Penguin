//! Кодирование целых переменной длины, как в QUIC.
//!
//! RFC 9000, §16. Два старших бита первого байта задают длину записи, а
//! остальные биты — часть значения:
//!
//! | Биты | Байт | Разрядность | Наибольшее значение |
//! |---|---|---|---|
//! | `00` | 1 | 6 | 63 |
//! | `01` | 2 | 14 | 16 383 |
//! | `10` | 4 | 30 | 1 073 741 823 |
//! | `11` | 8 | 62 | 4 611 686 018 427 387 903 |
//!
//! Своя реализация, а не заимствованная у `quinn`: тип `VarInt` из
//! `quinn-proto` не читается из асинхронного потока, а именно так varint
//! приходит в ответе на TCP-запрос — по одному байту, потому что до чтения
//! первого байта неизвестно, сколько их будет всего.

use std::io;

use bytes::{Buf, BufMut};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Наибольшее представимое значение.
pub const MAX: u64 = (1 << 62) - 1;

/// Сколько байт займёт значение.
pub const fn encoded_len(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

/// Записывает значение.
///
/// Значения больше [`MAX`] непредставимы; такое не может прийти из наших
/// собственных данных (длины буферов и номера кадров заведомо меньше), а
/// паниковать в коде, который держит соединение, нельзя — поэтому значение
/// обрезается до максимума.
pub fn encode(value: u64, buf: &mut impl BufMut) {
    let value = value.min(MAX);
    match encoded_len(value) {
        1 => buf.put_u8(value as u8),
        2 => buf.put_u16(value as u16 | 0b0100_0000 << 8),
        4 => buf.put_u32(value as u32 | 0b1000_0000 << 24),
        _ => buf.put_u64(value | 0b1100_0000 << 56),
    }
}

/// Читает значение из буфера.
///
/// `None` — байт не хватило. Буфер при этом не сдвигается, и вызов можно
/// повторить, дочитав данные.
pub fn decode(buf: &mut impl Buf) -> Option<u64> {
    if !buf.has_remaining() {
        return None;
    }
    let first = buf.chunk()[0];
    let len = length_from_prefix(first);
    if buf.remaining() < len {
        return None;
    }

    let mut value = u64::from(first & 0b0011_1111);
    buf.advance(1);
    for _ in 1..len {
        value = (value << 8) | u64::from(buf.get_u8());
    }
    Some(value)
}

/// Читает значение из асинхронного потока.
pub async fn read_from<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<u64> {
    let first = reader.read_u8().await?;
    let len = length_from_prefix(first);
    let mut value = u64::from(first & 0b0011_1111);
    for _ in 1..len {
        value = (value << 8) | u64::from(reader.read_u8().await?);
    }
    Ok(value)
}

/// Длина записи по первому байту.
const fn length_from_prefix(first: u8) -> usize {
    1 << (first >> 6)
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;

    fn round_trip(value: u64) -> Vec<u8> {
        let mut buf = BytesMut::new();
        encode(value, &mut buf);
        assert_eq!(buf.len(), encoded_len(value), "длина записи {value}");
        let mut reading = buf.clone().freeze();
        assert_eq!(decode(&mut reading), Some(value), "значение {value}");
        assert!(!reading.has_remaining(), "лишние байты после {value}");
        buf.to_vec()
    }

    #[test]
    fn encodes_boundaries() {
        // Границы всех четырёх длин — ровно там, где ошибка на единицу и живёт.
        for value in [0, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824, MAX] {
            round_trip(value);
        }
    }

    #[test]
    fn matches_rfc_examples() {
        // Примеры из приложения A.1 RFC 9000.
        assert_eq!(round_trip(37), vec![0x25]);
        assert_eq!(round_trip(15_293), vec![0x7b, 0xbd]);
        assert_eq!(round_trip(494_878_333), vec![0x9d, 0x7f, 0x3e, 0x7d]);
        assert_eq!(
            round_trip(151_288_809_941_952_652),
            vec![0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]
        );
    }

    #[test]
    fn decode_needs_all_bytes() {
        let mut buf = BytesMut::new();
        encode(15_293, &mut buf);
        let mut truncated = buf.freeze().slice(..1);
        assert_eq!(decode(&mut truncated), None);
        // Буфер не тронут — можно дочитать и повторить.
        assert_eq!(truncated.remaining(), 1);
    }

    #[tokio::test]
    async fn reads_from_stream() {
        let mut buf = BytesMut::new();
        for value in [0u64, 1, 63, 16_383, MAX] {
            encode(value, &mut buf);
        }
        let mut reader = std::io::Cursor::new(buf.to_vec());
        for value in [0u64, 1, 63, 16_383, MAX] {
            assert_eq!(read_from(&mut reader).await.expect("читается"), value);
        }
    }

    #[test]
    fn oversized_value_is_clamped_not_panicking() {
        let mut buf = BytesMut::new();
        encode(u64::MAX, &mut buf);
        let mut reading = buf.freeze();
        assert_eq!(decode(&mut reading), Some(MAX));
    }
}
