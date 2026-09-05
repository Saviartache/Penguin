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
//! Капсула типа `DATAGRAM` переносит по потоку то же самое, что кадр
//! `HTTP/3 DATAGRAM` переносит поверх QUIC напрямую (RFC 9297, §3.5:
//! «семантика одинакова»), только надёжно и по порядку, а не best-effort.
//! Этот крейт использует только этот путь — почему, написано в
//! [`crate::flow`].
//!
//! Приёмник обязан молча пропускать капсулы незнакомого типа и переходить к
//! следующей (RFC 9297, §3.2) — здесь это [`CapsuleReader::next_datagram`]:
//! он этим и занимается, а не сообщает об ошибке.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::MasqueError;
use crate::varint;

/// Тип капсулы `DATAGRAM` (RFC 9297, §3.5): несёт HTTP-датаграмму по потоку.
pub const CAPSULE_TYPE_DATAGRAM: u64 = 0x00;

/// Context ID для необработанной полезной нагрузки UDP (RFC 9298, §5).
///
/// Ненулевые ID зарезервированы под сжатие заголовков, которое этот документ
/// не определяет вовсе — здесь и в [`CapsuleReader`] такие просто пропускаются.
pub const CONTEXT_ID_UDP: u64 = 0;

/// Наибольшая полезная нагрузка при `Context ID = 0` (RFC 9298, §5).
pub const MAX_UDP_PAYLOAD: usize = 65527;

/// Собирает капсулу `DATAGRAM` с полезной нагрузкой UDP при `Context ID = 0`.
///
/// Возвращает ошибку конфигурации, а не обрезает нагрузку молча: пакет
/// длиннее предела — это то, что должен был поймать вызывающий раньше.
pub fn encode_udp_datagram(payload: &[u8]) -> Result<Bytes, MasqueError> {
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(MasqueError::malformed(format!(
            "датаграмма UDP длиннее {MAX_UDP_PAYLOAD} байт: {}",
            payload.len()
        )));
    }

    let mut value = BytesMut::with_capacity(varint::encoded_len(CONTEXT_ID_UDP) + payload.len());
    varint::encode(CONTEXT_ID_UDP, &mut value);
    value.put_slice(payload);

    Ok(encode_capsule(CAPSULE_TYPE_DATAGRAM, &value))
}

/// Собирает капсулу произвольного типа.
fn encode_capsule(capsule_type: u64, value: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(
        varint::encoded_len(capsule_type) + varint::encoded_len(value.len() as u64) + value.len(),
    );
    varint::encode(capsule_type, &mut buf);
    varint::encode(value.len() as u64, &mut buf);
    buf.put_slice(value);
    buf.freeze()
}

/// Собирает капсулы из последовательных кусков потока HTTP/3.
///
/// Кадр `DATA` не обязан совпадать по границам с капсулой: сервер вправе
/// прислать половину заголовка капсулы в одном кадре и остаток в следующем.
/// Поэтому байты копятся здесь, а не разбираются по мере поступления кадров.
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

    /// Возвращает полезную нагрузку следующей капсулы `DATAGRAM` при
    /// `Context ID = 0`, если она уже целиком собрана.
    ///
    /// Капсулы других типов и другие context ID пропускаются молча (RFC 9297,
    /// §3.2; RFC 9298, §5) — этот метод зовут в цикле, и он либо отдаёт
    /// нагрузку, либо говорит `Ok(None)`, когда данных, накопленных на
    /// сегодня, для целой капсулы не хватает.
    pub fn next_datagram(&mut self) -> Result<Option<Bytes>, MasqueError> {
        loop {
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

            if capsule_type != CAPSULE_TYPE_DATAGRAM {
                // Неизвестный тип — переходим к следующей капсуле.
                continue;
            }

            let mut value = frame.freeze();
            let context_id = varint::decode_prefix(&mut value)
                .ok_or_else(|| MasqueError::malformed("капсула DATAGRAM без context ID"))?;
            if context_id != CONTEXT_ID_UDP {
                // Контекст сжатия, которого этот клиент не регистрировал —
                // разбирать нечем, и RFC не определяет для него формат.
                continue;
            }

            return Ok(Some(value));
        }
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
        // Капсула типа 0x2a (не DATAGRAM), за ней — настоящая датаграмма.
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
}
