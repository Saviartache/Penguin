//! Датаграмма HTTP/3 (RFC 9297, §2.1).
//!
//! ```text
//!  HTTP/3 Datagram {
//!    Quarter Stream ID (i),
//!    HTTP Datagram Payload (..),
//!  }
//! ```
//!
//! Quarter Stream ID — номер потока запроса, делённый на четыре: запросы
//! идут по двунаправленным потокам клиента, номера которых кратны четырём.

use bytes::{BufMut, Bytes, BytesMut};

use super::code::H3_DATAGRAM_ERROR;
use super::error::{H3Error, H3Result};
use crate::varint;

/// Наибольший допустимый Quarter Stream ID: `2^60 - 1`.
const MAX_QUARTER_STREAM_ID: u64 = (1 << 60) - 1;

/// Собирает датаграмму для потока `stream_id`.
pub fn encode(stream_id: u64, payload: &[u8]) -> Bytes {
    let quarter = stream_id / 4;
    let mut out = BytesMut::with_capacity(varint::encoded_len(quarter) + payload.len());
    varint::encode(quarter, &mut out);
    out.put_slice(payload);
    out.freeze()
}

/// Разбирает датаграмму: номер потока и содержимое.
pub fn decode(mut datagram: Bytes) -> H3Result<(u64, Bytes)> {
    let (quarter, used) = varint::try_decode(&datagram).ok_or_else(|| {
        H3Error::protocol(H3_DATAGRAM_ERROR, "датаграмма короче Quarter Stream ID")
    })?;
    if quarter > MAX_QUARTER_STREAM_ID {
        return Err(H3Error::protocol(
            H3_DATAGRAM_ERROR,
            "Quarter Stream ID больше 2^60 - 1",
        ));
    }
    let payload = datagram.split_off(used);
    Ok((quarter * 4, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_datagram_names_its_stream_divided_by_four() {
        // Поток 8 → Quarter Stream ID 2, затем контекст 0 и данные.
        let datagram = encode(8, &[0x00, 0xaa]);
        assert_eq!(&datagram[..], &[0x02, 0x00, 0xaa]);
        let (stream_id, payload) = decode(datagram).expect("разбирается");
        assert_eq!(stream_id, 8);
        assert_eq!(&payload[..], &[0x00, 0xaa]);
    }

    #[test]
    fn an_empty_payload_is_allowed() {
        let (stream_id, payload) = decode(Bytes::from_static(&[0x00])).expect("разбирается");
        assert_eq!(stream_id, 0);
        assert!(payload.is_empty());
    }

    #[test]
    fn broken_datagrams_are_connection_errors() {
        for raw in [&[][..], &[0x40], &[0xd0, 0, 0, 0, 0, 0, 0, 0]] {
            let err = decode(Bytes::copy_from_slice(raw)).expect_err("ошибка");
            assert!(matches!(
                err,
                H3Error::Protocol {
                    code: H3_DATAGRAM_ERROR,
                    ..
                }
            ));
        }
    }
}
