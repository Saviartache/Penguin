//! Кадры HTTP/3: тип, длина, содержимое (RFC 9114, §7.1).

use bytes::{BufMut, Bytes, BytesMut};

use crate::varint;

/// `DATA` — тело сообщения (§7.2.1).
pub const DATA: u64 = 0x00;
/// `HEADERS` — блок полей QPACK (§7.2.2).
pub const HEADERS: u64 = 0x01;
/// `CANCEL_PUSH` (§7.2.3).
pub const CANCEL_PUSH: u64 = 0x03;
/// `SETTINGS` (§7.2.4).
pub const SETTINGS: u64 = 0x04;
/// `PUSH_PROMISE` (§7.2.5).
pub const PUSH_PROMISE: u64 = 0x05;
/// `GOAWAY` (§7.2.6).
pub const GOAWAY: u64 = 0x07;
/// `MAX_PUSH_ID` (§7.2.7).
pub const MAX_PUSH_ID: u64 = 0x0d;

/// Типы кадров HTTP/2 без пары в HTTP/3: `H3_FRAME_UNEXPECTED` (§7.2.8).
pub fn is_reserved_http2(kind: u64) -> bool {
    matches!(kind, 0x02 | 0x06 | 0x08 | 0x09)
}

/// Заголовок кадра.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Тип кадра.
    pub kind: u64,
    /// Длина содержимого.
    pub len: u64,
}

/// Заголовок кадра и его длина на проводе; `None` — байт не хватает.
pub fn decode_header(buf: &[u8]) -> Option<(FrameHeader, usize)> {
    let (kind, kind_len) = varint::try_decode(buf)?;
    let (len, len_len) = varint::try_decode(&buf[kind_len..])?;
    Some((FrameHeader { kind, len }, kind_len + len_len))
}

/// Дописывает заголовок кадра.
pub fn encode_header(kind: u64, len: u64, out: &mut impl BufMut) {
    varint::encode(kind, out);
    varint::encode(len, out);
}

/// Собирает кадр целиком.
pub fn encode(kind: u64, payload: &[u8]) -> Bytes {
    let len = payload.len() as u64;
    let mut out = BytesMut::with_capacity(
        varint::encoded_len(kind) + varint::encoded_len(len) + payload.len(),
    );
    encode_header(kind, len, &mut out);
    out.put_slice(payload);
    out.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_header_round_trips() {
        let frame = encode(HEADERS, &[0xaa; 70]);
        assert_eq!(&frame[..3], &[0x01, 0x40, 0x46]);
        let (header, used) = decode_header(&frame).expect("заголовок целиком");
        assert_eq!(
            header,
            FrameHeader {
                kind: HEADERS,
                len: 70
            }
        );
        assert_eq!(used, 3);
    }

    #[test]
    fn a_partial_header_asks_for_more() {
        assert_eq!(decode_header(&[0x01]), None);
        assert_eq!(decode_header(&[0x01, 0x40]), None);
    }

    #[test]
    fn http2_leftovers_are_recognised() {
        for kind in [0x02, 0x06, 0x08, 0x09] {
            assert!(is_reserved_http2(kind));
        }
        assert!(!is_reserved_http2(DATA));
        assert!(!is_reserved_http2(0x21));
    }
}
