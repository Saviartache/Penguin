//! Кадр gRPC (флаг сжатия 0, длина u32 BE, сообщение) с `Hunk { bytes data = 1; }`
//! (Xray `transport/internet/grpc/encoding/stream.proto`): ключ `0x0A`, длина-варинт, байты;
//! пустой `Hunk` — пустое сообщение.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::{TransportError, TransportResult};

/// Длина префикса кадра gRPC.
const PREFIX: usize = 5;

/// Ключ поля `data`: номер 1, тип «длина и байты».
const DATA_KEY: u64 = (1 << 3) | 2;

/// Предел сообщения разборщика (защита памяти).
const MAX_MESSAGE: usize = 1 << 20;

/// Собирает кадр gRPC с `Hunk { data }`.
pub fn encode_hunk(data: &[u8]) -> Bytes {
    let mut out = BytesMut::new();
    put_hunk(data, &mut out);
    out.freeze()
}

/// Дописывает кадр gRPC с `Hunk { data }` в `out` без промежуточных буферов.
pub fn put_hunk(data: &[u8], out: &mut impl BufMut) {
    let message_len = if data.is_empty() {
        0
    } else {
        1 + varint_len(data.len() as u64) + data.len()
    };
    out.put_u8(0);
    out.put_u32(message_len as u32);
    if !data.is_empty() {
        put_varint(DATA_KEY, out);
        put_varint(data.len() as u64, out);
        out.put_slice(data);
    }
}

fn varint_len(value: u64) -> usize {
    (64 - (value | 1).leading_zeros() as usize).div_ceil(7)
}

/// Собирает сообщения из кусков тела ответа.
#[derive(Debug, Default)]
pub struct Deframer {
    buf: BytesMut,
}

impl Deframer {
    /// Добавляет кусок тела.
    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.put_slice(chunk);
    }

    /// Данные следующего целиком пришедшего `Hunk`. `None` — ждать ещё.
    pub fn next_hunk(&mut self) -> TransportResult<Option<Bytes>> {
        if self.buf.len() < PREFIX {
            return Ok(None);
        }
        if self.buf[0] != 0 {
            return Err(TransportError::malformed("сжатое сообщение gRPC"));
        }
        let len = u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
        if len > MAX_MESSAGE {
            return Err(TransportError::malformed(format!(
                "сообщение gRPC в {len} байт"
            )));
        }
        if self.buf.len() < PREFIX + len {
            return Ok(None);
        }
        self.buf.advance(PREFIX);
        let message = self.buf.split_to(len).freeze();
        decode_hunk(message).map(Some)
    }
}

/// Достаёт `data` из `Hunk`; незнакомые поля пропускаются, как велит protobuf.
fn decode_hunk(mut message: Bytes) -> TransportResult<Bytes> {
    let mut data = Bytes::new();
    while message.has_remaining() {
        let key = get_varint(&mut message)?;
        match key & 7 {
            0 => {
                get_varint(&mut message)?;
            }
            1 => skip(&mut message, 8)?,
            2 => {
                let len = usize::try_from(get_varint(&mut message)?).map_err(|_| truncated())?;
                if message.remaining() < len {
                    return Err(truncated());
                }
                let value = message.split_to(len);
                if key == DATA_KEY {
                    data = value;
                }
            }
            5 => skip(&mut message, 4)?,
            _ => return Err(TransportError::malformed("неизвестный тип поля protobuf")),
        }
    }
    Ok(data)
}

fn skip(message: &mut Bytes, len: usize) -> TransportResult<()> {
    if message.remaining() < len {
        return Err(truncated());
    }
    message.advance(len);
    Ok(())
}

/// Варинт protobuf: по семь бит, младшие вперёд.
fn put_varint(mut value: u64, out: &mut impl BufMut) {
    while value >= 0x80 {
        out.put_u8(value as u8 | 0x80);
        value >>= 7;
    }
    out.put_u8(value as u8);
}

fn get_varint(message: &mut Bytes) -> TransportResult<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        if !message.has_remaining() {
            return Err(truncated());
        }
        let byte = message.get_u8();
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(TransportError::malformed("варинт protobuf длиннее 64 бит"))
}

fn truncated() -> TransportError {
    TransportError::malformed("сообщение gRPC обрезано")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hunk_is_laid_out_like_protobuf() {
        // Внешнего вектора нет: раскладка по `stream.proto` Xray
        let frame = encode_hunk(b"abc");
        assert_eq!(&frame[..], &[0, 0, 0, 0, 5, 0x0a, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn varint_len_matches_the_encoder() {
        for value in [0u64, 1, 127, 128, 300, 16_383, 16_384, 1 << 20, u64::MAX] {
            let mut buf = Vec::new();
            put_varint(value, &mut buf);
            assert_eq!(varint_len(value), buf.len(), "{value}");
        }
    }

    #[test]
    fn an_empty_hunk_is_an_empty_message() {
        assert_eq!(&encode_hunk(b"")[..], &[0, 0, 0, 0, 0]);
    }

    #[test]
    fn a_long_hunk_has_a_multibyte_length() {
        let data = vec![7u8; 300];
        let frame = encode_hunk(&data);
        assert_eq!(&frame[5..8], &[0x0a, 0xac, 0x02]);
        let mut deframer = Deframer::default();
        deframer.push(&frame);
        assert_eq!(
            deframer.next_hunk().expect("разбор").as_deref(),
            Some(&data[..])
        );
    }

    #[test]
    fn hunks_split_across_chunks_assemble() {
        let mut wire = encode_hunk(b"one").to_vec();
        wire.extend_from_slice(&encode_hunk(b"two"));
        let mut deframer = Deframer::default();
        deframer.push(&wire[..4]);
        assert_eq!(deframer.next_hunk().expect("разбор"), None);
        deframer.push(&wire[4..9]);
        assert_eq!(deframer.next_hunk().expect("разбор"), None);
        deframer.push(&wire[9..]);
        assert_eq!(
            deframer.next_hunk().expect("разбор").as_deref(),
            Some(&b"one"[..])
        );
        assert_eq!(
            deframer.next_hunk().expect("разбор").as_deref(),
            Some(&b"two"[..])
        );
        assert_eq!(deframer.next_hunk().expect("разбор"), None);
    }

    #[test]
    fn unknown_fields_are_skipped() {
        let message = [0x10, 0x01, 0x0a, 0x01, b'x'];
        let mut wire = vec![0, 0, 0, 0, message.len() as u8];
        wire.extend_from_slice(&message);
        let mut deframer = Deframer::default();
        deframer.push(&wire);
        assert_eq!(
            deframer.next_hunk().expect("разбор").as_deref(),
            Some(&b"x"[..])
        );
    }

    #[test]
    fn compression_and_huge_messages_are_refused() {
        let mut deframer = Deframer::default();
        deframer.push(&[1, 0, 0, 0, 0]);
        assert!(deframer.next_hunk().is_err());

        let mut deframer = Deframer::default();
        deframer.push(&[0, 0xff, 0, 0, 0]);
        assert!(deframer.next_hunk().is_err());
    }
}
