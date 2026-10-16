//! Инкапсуляция датаграмм UDP ASSOCIATE.
//!
//! ```text
//! ┌────────┬──────┬──────┬────────┬────────┐
//! │ RSV 2Б │ FRAG │ ATYP │ АДРЕС  │ ДАННЫЕ │
//! └────────┴──────┴──────┴────────┴────────┘
//! ```
//!
//! Фрагментированные датаграммы (`FRAG` != 0) отбрасываются.

use bytes::{BufMut, BytesMut};
use penguin_core::address::SocketAddress;

use super::address;

/// Разобранная датаграмма от клиента.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    /// Куда клиент просит отправить.
    pub target: SocketAddress,
    /// Что отправить.
    pub payload: &'a [u8],
}

/// Разбирает датаграмму; `None` — повреждена или фрагментирована.
pub fn decode(datagram: &[u8]) -> Option<Packet<'_>> {
    // RSV(2) + FRAG(1)
    if datagram.len() < 3 || datagram[2] != 0 {
        return None;
    }

    let (target, consumed) = address::decode(&datagram[3..])?;
    let payload = datagram.get(3 + consumed..)?;
    Some(Packet { target, payload })
}

/// Собирает датаграмму для клиента.
pub fn encode(source: &SocketAddress, payload: &[u8]) -> BytesMut {
    let mut buf = BytesMut::new();
    encode_into(&mut buf, source, payload);
    buf
}

/// Собирает датаграмму в `buf`, затирая его содержимое; буфер можно переиспользовать.
pub fn encode_into(buf: &mut BytesMut, source: &SocketAddress, payload: &[u8]) {
    buf.clear();
    buf.reserve(3 + 262 + payload.len());
    buf.put_u16(0);
    buf.put_u8(0);
    address::encode(source, buf);
    buf.put_slice(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let source: SocketAddress = "1.2.3.4:53".parse().expect("адрес");
        let encoded = encode(&source, b"hello");
        let decoded = decode(&encoded).expect("разбирается");
        assert_eq!(decoded.target, source);
        assert_eq!(decoded.payload, b"hello");
    }

    #[test]
    fn round_trips_domain_target() {
        let target: SocketAddress = "example.com:443".parse().expect("адрес");
        let encoded = encode(&target, b"payload");
        assert_eq!(decode(&encoded).expect("разбирается").target, target);
    }

    #[test]
    fn reused_buffer_is_overwritten() {
        let source: SocketAddress = "1.2.3.4:53".parse().expect("адрес");
        let mut buf = encode(&source, b"first message");
        encode_into(&mut buf, &source, b"x");
        assert_eq!(decode(&buf).expect("разбирается").payload, b"x");
    }

    #[test]
    fn rejects_fragments() {
        let mut encoded = encode(&"1.2.3.4:53".parse().expect("адрес"), b"x");
        encoded[2] = 1;
        assert!(decode(&encoded).is_none());
    }

    #[test]
    fn rejects_truncated() {
        let encoded = encode(&"1.2.3.4:53".parse().expect("адрес"), b"payload");
        for cut in 0..encoded.len() - b"payload".len() {
            assert!(
                decode(&encoded[..cut]).is_none(),
                "разобрал обрезанное на {cut}"
            );
        }
    }

    #[test]
    fn empty_payload_is_valid() {
        let encoded = encode(&"1.2.3.4:53".parse().expect("адрес"), b"");
        let decoded = decode(&encoded).expect("разбирается");
        assert!(decoded.payload.is_empty());
    }
}
