//! Датаграмма внутри потока.
//!
//! ```text
//! +------+----------+----------+--------+------+----------+
//! | ATYP | DST.ADDR | DST.PORT | Length | CRLF |  данные  |
//! +------+----------+----------+--------+------+----------+
//! |  1   | сколько  |    2     |   2    |  2   | сколько  |
//! +------+----------+----------+--------+------+----------+
//! ```
//!
//! Адрес стоит на каждой посылке: один поток обслуживает всю UDP-сессию. Длина
//! восстанавливает границы в потоке TLS, `CRLF` после неё проверяет, что читается заголовок.

use std::ops::Range;

use penguin_core::address::SocketAddress;
use penguin_transport::addr::socks;

use crate::error::{TrojanError, TrojanResult};
use crate::frame::request::CRLF;

/// Наибольшая датаграмма, которую принимаем (предел UDP).
pub const MAX_PAYLOAD: usize = 65_535;

/// Дописывает датаграмму для отправки в `out`.
pub fn encode_into(out: &mut Vec<u8>, target: &SocketAddress, payload: &[u8]) -> TrojanResult<()> {
    let len = u16::try_from(payload.len()).map_err(|_| TrojanError::Oversized(payload.len()))?;

    out.reserve(socks::encoded_len(target) + 4 + payload.len());
    socks::encode(target, out)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&CRLF);
    out.extend_from_slice(payload);
    Ok(())
}

/// Собирает датаграмму для отправки в поток.
pub fn encode(target: &SocketAddress, payload: &[u8]) -> TrojanResult<Vec<u8>> {
    let mut out = Vec::new();
    encode_into(&mut out, target, payload)?;
    Ok(out)
}

/// Читает датаграмму с начала среза: адрес отправителя и границы данных (`range.end` — съедено).
/// `Ok(None)` — пришло не всё, это обычное дело в потоке.
pub fn decode(bytes: &[u8]) -> TrojanResult<Option<(SocketAddress, Range<usize>)>> {
    let Some((source, used)) = socks::decode(bytes)? else {
        return Ok(None);
    };

    let Some(len) = bytes.get(used..).and_then(<[u8]>::first_chunk::<2>) else {
        return Ok(None);
    };
    let len = usize::from(u16::from_be_bytes(*len));

    let Some(crlf) = bytes.get(used + 2..).and_then(<[u8]>::first_chunk::<2>) else {
        return Ok(None);
    };
    // Границу не восстановить: поток дальше не читается
    if *crlf != CRLF {
        return Err(TrojanError::malformed(
            "после длины датаграммы нет CRLF: поток разъехался",
        ));
    }

    let start = used + 4;
    if bytes.len() < start + len {
        return Ok(None);
    }
    Ok(Some((source, start..start + len)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(raw: &str, port: u16) -> SocketAddress {
        SocketAddress::ip(raw.parse().expect("адрес"), port)
    }

    #[test]
    fn a_datagram_survives_the_round_trip() {
        for target in [
            ip("203.0.113.5", 53),
            ip("2001:db8::1", 53),
            SocketAddress::domain("dns.example.com", 53),
        ] {
            let wrapped = encode(&target, b"\x00\x01payload").expect("собирается");
            let (back, range) = decode(&wrapped).expect("разбирается").expect("целиком");

            assert_eq!(back, target);
            assert_eq!(&wrapped[range.clone()], b"\x00\x01payload");
            assert_eq!(range.end, wrapped.len(), "съедено не всё");
        }
    }

    #[test]
    fn the_bytes_are_where_the_protocol_says() {
        let wrapped = encode(&ip("203.0.113.5", 53), b"xy").expect("собирается");
        assert_eq!(
            wrapped,
            [
                0x01, 203, 0, 113, 5, 0x00, 0x35, 0x00, 0x02, 0x0D, 0x0A, b'x', b'y'
            ]
        );
    }

    #[test]
    fn two_datagrams_in_one_chunk_are_read_one_by_one() {
        let first = encode(&ip("203.0.113.5", 53), b"one").expect("собирается");
        let second = encode(&ip("198.51.100.9", 5353), b"two").expect("собирается");
        let mut stream = first.clone();
        stream.extend_from_slice(&second);

        let (_, range) = decode(&stream).expect("разбирается").expect("целиком");
        assert_eq!(&stream[range.clone()], b"one");
        assert_eq!(range.end, first.len());

        let rest = &stream[range.end..];
        let (_, range) = decode(rest).expect("разбирается").expect("целиком");
        assert_eq!(&rest[range.clone()], b"two");
        assert_eq!(range.end, second.len());
    }

    #[test]
    fn a_datagram_arriving_in_pieces_is_not_an_error() {
        let full =
            encode(&SocketAddress::domain("dns.example.com", 53), b"payload").expect("собирается");

        for cut in 0..full.len() {
            assert!(
                decode(&full[..cut]).expect("не сломано").is_none(),
                "обрезанная до {cut} байт датаграмма разобралась целиком"
            );
        }
    }

    #[test]
    fn an_empty_payload_is_still_a_datagram() {
        let wrapped = encode(&ip("203.0.113.5", 53), b"").expect("собирается");
        let (_, range) = decode(&wrapped).expect("разбирается").expect("целиком");
        assert!(range.is_empty());
        assert_eq!(range.end, wrapped.len());
    }

    #[test]
    fn a_missing_crlf_stops_the_stream() {
        let mut wrapped = encode(&ip("203.0.113.5", 53), b"xy").expect("собирается");
        wrapped[9] = b'!';
        assert!(decode(&wrapped).is_err());
    }

    #[test]
    fn a_datagram_too_big_to_announce_is_refused() {
        let huge = vec![0u8; MAX_PAYLOAD + 1];
        assert!(encode(&ip("203.0.113.5", 53), &huge).is_err());
    }
}
