//! Капсулы RFC 9297: датаграммы внутри потока, когда QUIC недоступен.
//!
//! ```text
//!  Capsule Type (i) = 0 ‖ Length (i) ‖ содержимое датаграммы (как в `udp`)
//! ```
//!
//! Капсулы чужих типов пропускаются (RFC 9297, §3.2).

use bytes::{Buf, Bytes, BytesMut};
use penguin_transport::varint;

use crate::error::{PingwinError, PingwinResult};

/// Тип капсулы `DATAGRAM`.
const DATAGRAM: u64 = 0;

/// Наибольшая капсула: датаграмма UDP и самый длинный адрес SOCKS5.
pub const MAX_LEN: usize = 64 * 1024 + 1 + 1 + 1 + 255 + 2;

/// Дописывает капсулу `DATAGRAM` с содержимым `payload` в `out`.
pub fn encode_into(payload: &[u8], out: &mut Vec<u8>) {
    out.reserve(varint::encoded_len(DATAGRAM) + varint::encoded_len(payload.len() as u64));
    varint::encode(DATAGRAM, out);
    varint::encode(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

/// Достаёт из `buf` содержимое следующей `DATAGRAM`; `None` — капсула пришла не вся.
pub fn decode(buf: &mut BytesMut) -> PingwinResult<Option<Bytes>> {
    loop {
        let Some((kind, kind_len)) = varint::try_decode(buf) else {
            return Ok(None);
        };
        let Some((len, len_len)) = varint::try_decode(&buf[kind_len..]) else {
            return Ok(None);
        };
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        if len > MAX_LEN {
            return Err(PingwinError::malformed(format!(
                "капсула длиной {len} байт: больше любой датаграммы"
            )));
        }
        let header = kind_len + len_len;
        if buf.len() < header + len {
            return Ok(None);
        }
        buf.advance(header);
        let body = buf.split_to(len).freeze();
        if kind == DATAGRAM {
            return Ok(Some(body));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_capsule_is_read() {
        // Тип 0, длина 3, «abc» (RFC 9297, §3.2).
        let mut buf = BytesMut::from(&[0u8, 3, b'a', b'b', b'c'][..]);
        assert_eq!(
            decode(&mut buf).expect("разбирается").as_deref(),
            Some(&b"abc"[..])
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn the_written_capsule_matches_the_recorded_one() {
        let mut out = Vec::new();
        encode_into(b"abc", &mut out);
        assert_eq!(out, [0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn a_capsule_cut_in_half_waits_for_the_rest() {
        let mut out = Vec::new();
        encode_into(&[7u8; 300], &mut out);
        let mut buf = BytesMut::from(&out[..100]);
        assert!(decode(&mut buf).expect("не ошибка").is_none());
        buf.extend_from_slice(&out[100..]);
        assert_eq!(decode(&mut buf).expect("дошла").map(|b| b.len()), Some(300));
    }

    #[test]
    fn a_foreign_capsule_is_skipped() {
        // Тип 0x29 (длинная запись: 0x40 0x29), длина 1; затем DATAGRAM «x».
        let mut buf = BytesMut::from(&[0x40u8, 0x29, 1, 0xFF, 0, 1, b'x'][..]);
        assert_eq!(
            decode(&mut buf).expect("разбирается").as_deref(),
            Some(&b"x"[..])
        );
    }

    #[test]
    fn an_absurd_length_is_refused() {
        // Длина 2^22 (четырёхбайтная запись).
        let mut buf = BytesMut::from(&[0u8, 0x80, 0x40, 0, 0][..]);
        assert!(decode(&mut buf).is_err());
    }
}
