//! Протокол капсул (RFC 9297, §3.2) и датаграмма UDP-проксирования (RFC 9298, §5).
//!
//! ```text
//!  Capsule {
//!    Type (varint),
//!    Length (varint),
//!    Value (Length байт),
//!  }
//!
//!  Value капсулы DATAGRAM (тип 0x00, RFC 9297 §3.5) —
//!  это в точности содержимое датаграммы HTTP:
//!
//!  UDP Proxying HTTP Datagram Payload {
//!    Context ID (varint),
//!    UDP Proxying Payload (остаток),
//!  }
//! ```
//!
//! Капсула `DATAGRAM` несёт то же, что кадр `HTTP/3 DATAGRAM` (RFC 9297, §3.5),
//! но надёжно (выбор пути — в [`crate::flow`]). Капсулы незнакомого типа
//! пропускаются молча (RFC 9297, §3.2).

use bytes::{Buf, BufMut, Bytes, BytesMut};
use penguin_transport::varint;

use crate::error::MasqueError;

/// Тип капсулы `DATAGRAM` (RFC 9297, §3.5): несёт HTTP-датаграмму по потоку.
pub const CAPSULE_TYPE_DATAGRAM: u64 = 0x00;

/// Context ID нагрузки UDP (RFC 9298, §5); ненулевые пропускаются.
pub const CONTEXT_ID_UDP: u64 = 0;

/// Наибольшая полезная нагрузка при `Context ID = 0` (RFC 9298, §5).
pub const MAX_UDP_PAYLOAD: usize = 65527;

/// Капсула `DATAGRAM` с нагрузкой UDP при `Context ID = 0`; слишком длинный пакет — ошибка.
pub fn encode_udp_datagram(payload: &[u8]) -> Result<Bytes, MasqueError> {
    check_udp_len(payload)?;
    Ok(encode_datagram_capsule(CONTEXT_ID_UDP, payload))
}

/// Содержимое датаграммы HTTP с нагрузкой UDP: `Context ID = 0` и пакет (RFC 9298, §5).
pub fn encode_udp_payload(payload: &[u8]) -> Result<Bytes, MasqueError> {
    check_udp_len(payload)?;
    Ok(encode_datagram_payload(CONTEXT_ID_UDP, payload))
}

fn check_udp_len(payload: &[u8]) -> Result<(), MasqueError> {
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(MasqueError::malformed(format!(
            "датаграмма UDP длиннее {MAX_UDP_PAYLOAD} байт: {}",
            payload.len()
        )));
    }
    Ok(())
}

/// Нагрузка UDP из датаграммы HTTP; `None` — чужой контекст.
pub fn decode_udp_payload(mut value: Bytes) -> Result<Option<Bytes>, MasqueError> {
    let context_id = varint::decode_prefix(&mut value)
        .ok_or_else(|| MasqueError::malformed("датаграмма HTTP без context ID"))?;
    Ok((context_id == CONTEXT_ID_UDP).then_some(value))
}

/// Капсула `DATAGRAM` с произвольным Context ID (CONNECT-UDP и CONNECT-IP, RFC 9484 §6).
pub(crate) fn encode_datagram_capsule(context_id: u64, payload: &[u8]) -> Bytes {
    let value_len = varint::encoded_len(context_id) + payload.len();
    let mut buf = BytesMut::with_capacity(
        varint::encoded_len(CAPSULE_TYPE_DATAGRAM)
            + varint::encoded_len(value_len as u64)
            + value_len,
    );
    varint::encode(CAPSULE_TYPE_DATAGRAM, &mut buf);
    varint::encode(value_len as u64, &mut buf);
    varint::encode(context_id, &mut buf);
    buf.put_slice(payload);
    buf.freeze()
}

fn encode_datagram_payload(context_id: u64, payload: &[u8]) -> Bytes {
    let mut value = BytesMut::with_capacity(varint::encoded_len(context_id) + payload.len());
    varint::encode(context_id, &mut value);
    value.put_slice(payload);
    value.freeze()
}

/// Собирает капсулу произвольного типа.
pub(crate) fn encode_capsule(capsule_type: u64, value: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(
        varint::encoded_len(capsule_type) + varint::encoded_len(value.len() as u64) + value.len(),
    );
    varint::encode(capsule_type, &mut buf);
    varint::encode(value.len() as u64, &mut buf);
    buf.put_slice(value);
    buf.freeze()
}

/// Собирает капсулы из кусков потока HTTP/3 (границы `DATA` и капсул не совпадают).
#[derive(Default)]
pub struct CapsuleReader {
    buf: BytesMut,
}

impl CapsuleReader {
    /// Пустой читатель.
    pub fn new() -> Self {
        Self::default()
    }

    /// Добавляет очередной кусок, пришедший из `poll_recv_data`.
    pub fn push(&mut self, chunk: impl Buf) {
        self.buf.put(chunk);
    }

    /// Нагрузка следующей целой капсулы `DATAGRAM` с `Context ID = 0`;
    /// прочие пропускаются, `Ok(None)` — данных не хватает.
    pub fn next_datagram(&mut self) -> Result<Option<Bytes>, MasqueError> {
        loop {
            let Some((capsule_type, value)) = self.next_capsule()? else {
                return Ok(None);
            };
            if capsule_type != CAPSULE_TYPE_DATAGRAM {
                continue;
            }
            if let Some(payload) = decode_udp_payload(value)? {
                return Ok(Some(payload));
            }
        }
    }

    /// Следующая целая капсула как есть (тип, значение); `Ok(None)` — данных не хватает.
    pub fn next_capsule(&mut self) -> Result<Option<(u64, Bytes)>, MasqueError> {
        let Some((capsule_type, type_len)) = varint::try_decode(&self.buf) else {
            return Ok(None);
        };
        let Some((length, length_len)) = varint::try_decode(&self.buf[type_len..]) else {
            return Ok(None);
        };
        let header_len = type_len + length_len;
        let total_len = header_len
            + usize::try_from(length)
                .map_err(|_| MasqueError::malformed("длина капсулы не влезает в память"))?;

        if self.buf.len() < total_len {
            return Ok(None);
        }

        let mut frame = self.buf.split_to(total_len);
        frame.advance(header_len);
        Ok(Some((capsule_type, frame.freeze())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_udp_datagram_capsule_round_trips() {
        let payload = b"\xde\xad\xbe\xef";
        let capsule = encode_udp_datagram(payload).expect("нагрузка в пределах");

        let mut reader = CapsuleReader::new();
        reader.push(capsule);
        let decoded = reader
            .next_datagram()
            .expect("разбирается")
            .expect("капсула целиком пришла");
        assert_eq!(&decoded[..], payload);
    }

    #[test]
    fn a_datagram_payload_names_its_context() {
        let payload = encode_udp_payload(b"dns").expect("в пределах");
        assert_eq!(&payload[..], b"\x00dns");
        assert_eq!(
            decode_udp_payload(payload).expect("разбирается").as_deref(),
            Some(&b"dns"[..])
        );
        assert_eq!(
            decode_udp_payload(Bytes::from_static(b"\x02dns")).expect("разбирается"),
            None
        );
        assert!(decode_udp_payload(Bytes::new()).is_err());
    }

    #[test]
    fn an_oversized_payload_is_refused_before_it_is_sent() {
        let payload = vec![0u8; MAX_UDP_PAYLOAD + 1];
        assert!(encode_udp_datagram(&payload).is_err());
    }

    #[test]
    fn a_capsule_split_across_two_chunks_still_assembles() {
        let capsule = encode_udp_datagram(b"hello").expect("нагрузка в пределах");
        let (first, second) = capsule.split_at(2);

        let mut reader = CapsuleReader::new();
        reader.push(Bytes::copy_from_slice(first));
        assert_eq!(reader.next_datagram().expect("разбирается"), None);

        reader.push(Bytes::copy_from_slice(second));
        let decoded = reader
            .next_datagram()
            .expect("разбирается")
            .expect("теперь целиком");
        assert_eq!(&decoded[..], b"hello");
    }

    #[test]
    fn an_unknown_capsule_type_is_skipped_not_reported() {
        let mut buf = BytesMut::new();
        varint::encode(0x2a, &mut buf);
        varint::encode(3, &mut buf);
        buf.put_slice(b"xyz");
        buf.extend_from_slice(&encode_udp_datagram(b"real").expect("нагрузка в пределах"));

        let mut reader = CapsuleReader::new();
        reader.push(buf.freeze());
        let decoded = reader
            .next_datagram()
            .expect("незнакомый тип не считается ошибкой")
            .expect("вторая капсула — DATAGRAM");
        assert_eq!(&decoded[..], b"real");
    }

    #[test]
    fn two_datagrams_in_one_push_both_come_back() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&encode_udp_datagram(b"one").expect("в пределах"));
        buf.extend_from_slice(&encode_udp_datagram(b"two").expect("в пределах"));

        let mut reader = CapsuleReader::new();
        reader.push(buf.freeze());
        assert_eq!(
            &reader.next_datagram().expect("разбирается").unwrap()[..],
            b"one"
        );
        assert_eq!(
            &reader.next_datagram().expect("разбирается").unwrap()[..],
            b"two"
        );
        assert_eq!(reader.next_datagram().expect("разбирается"), None);
    }

    #[test]
    fn next_capsule_returns_a_type_next_datagram_does_not_know() {
        let mut buf = BytesMut::new();
        varint::encode(0x2a, &mut buf);
        varint::encode(3, &mut buf);
        buf.put_slice(b"xyz");

        let mut reader = CapsuleReader::new();
        reader.push(buf.freeze());
        let (capsule_type, value) = reader
            .next_capsule()
            .expect("разбирается")
            .expect("капсула целиком пришла");
        assert_eq!(capsule_type, 0x2a);
        assert_eq!(&value[..], b"xyz");
        assert_eq!(reader.next_capsule().expect("разбирается"), None);
    }
}
