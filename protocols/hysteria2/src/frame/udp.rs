//! UDPMessage: идентификаторы сессии и пакета, фрагменты, адрес.
//!
//! ```text
//! ┌────────────────────────────┐
//! │ u32     идентификатор сессии
//! │ u16     идентификатор пакета
//! │ u8      номер фрагмента
//! │ u8      всего фрагментов
//! │ varint  длина адреса
//! │ bytes   адрес
//! │ bytes   данные (до конца датаграммы)
//! └────────────────────────────┘
//! ```
//!
//! Сообщение едет в датаграмме QUIC, а не в потоке: поток дал бы гарантию
//! доставки и порядка, которых у UDP нет и быть не должно. Приложение,
//! рассчитывающее на потери, получило бы вместо них задержку.
//!
//! Отсюда же фрагментация: датаграмма QUIC ограничена путевым MTU, а UDP
//! приложения — нет.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::padding::MAX_ADDRESS_LENGTH;
use super::varint;

/// Длина неизменной части заголовка: сессия, пакет, фрагменты.
const FIXED_HEADER_LEN: usize = 4 + 2 + 1 + 1;

/// Наибольшее число фрагментов одной датаграммы.
///
/// Номер фрагмента занимает один байт, так что больше и не выразить.
pub const MAX_FRAGMENTS: u8 = u8::MAX;

/// Одно сообщение UDP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage {
    /// Сессия: одна на каждый UDP-сокет приложения.
    pub session_id: u32,
    /// Пакет внутри сессии. Общий у всех фрагментов одной датаграммы.
    pub packet_id: u16,
    /// Номер фрагмента, с нуля.
    pub fragment_id: u8,
    /// Всего фрагментов. Единица — датаграмма целая.
    pub fragment_count: u8,
    /// Адрес: назначение при отправке, отправитель при приёме.
    pub address: String,
    /// Данные.
    pub payload: Bytes,
}

impl UdpMessage {
    /// Длина сообщения в байтах.
    pub fn encoded_len(&self) -> usize {
        FIXED_HEADER_LEN
            + varint::encoded_len(self.address.len() as u64)
            + self.address.len()
            + self.payload.len()
    }

    /// Длина заголовка без данных.
    fn header_len(address_len: usize) -> usize {
        FIXED_HEADER_LEN + varint::encoded_len(address_len as u64) + address_len
    }

    /// Записывает сообщение.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.encoded_len());
        buf.put_u32(self.session_id);
        buf.put_u16(self.packet_id);
        buf.put_u8(self.fragment_id);
        buf.put_u8(self.fragment_count);
        varint::encode(self.address.len() as u64, &mut buf);
        buf.put_slice(self.address.as_bytes());
        buf.put_slice(&self.payload);
        buf.freeze()
    }

    /// Разбирает сообщение.
    ///
    /// `None` — датаграмма повреждена или обрезана. Ошибку возвращать некому:
    /// на той стороне UDP, и единственное разумное действие — молча выбросить.
    pub fn decode(mut buf: Bytes) -> Option<Self> {
        if buf.remaining() < FIXED_HEADER_LEN {
            return None;
        }
        let session_id = buf.get_u32();
        let packet_id = buf.get_u16();
        let fragment_id = buf.get_u8();
        let fragment_count = buf.get_u8();

        let address_len = varint::decode(&mut buf)?;
        if address_len > MAX_ADDRESS_LENGTH || buf.remaining() < address_len as usize {
            return None;
        }
        let address = buf.split_to(address_len as usize);
        let address = String::from_utf8(address.to_vec()).ok()?;

        Some(Self {
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            address,
            payload: buf,
        })
    }

    /// Датаграмма целая, собирать нечего.
    pub fn is_whole(&self) -> bool {
        self.fragment_count <= 1
    }
}

/// Режет датаграмму на фрагменты, умещающиеся в `max_datagram_size`.
///
/// Возвращает `None`, если фрагментов вышло бы больше, чем помещается в
/// однобайтовый счётчик: такую датаграмму отправить нельзя, и притворяться,
/// что отправили, нечестно.
pub fn fragment(
    session_id: u32,
    packet_id: u16,
    address: &str,
    payload: Bytes,
    max_datagram_size: usize,
) -> Option<Vec<UdpMessage>> {
    let header = UdpMessage::header_len(address.len());
    let capacity = max_datagram_size.checked_sub(header).filter(|c| *c > 0)?;

    if payload.len() <= capacity {
        return Some(vec![UdpMessage {
            session_id,
            packet_id,
            fragment_id: 0,
            fragment_count: 1,
            address: address.to_owned(),
            payload,
        }]);
    }

    let count = payload.len().div_ceil(capacity);
    if count > MAX_FRAGMENTS as usize {
        return None;
    }

    let mut parts = Vec::with_capacity(count);
    for (index, chunk) in payload.chunks(capacity).enumerate() {
        parts.push(UdpMessage {
            session_id,
            packet_id,
            fragment_id: index as u8,
            fragment_count: count as u8,
            address: address.to_owned(),
            payload: Bytes::copy_from_slice(chunk),
        });
    }
    Some(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(payload: &[u8]) -> UdpMessage {
        UdpMessage {
            session_id: 0xDEAD_BEEF,
            packet_id: 0x1234,
            fragment_id: 0,
            fragment_count: 1,
            address: "example.com:53".to_owned(),
            payload: Bytes::copy_from_slice(payload),
        }
    }

    #[test]
    fn round_trips() {
        let original = message(b"hello");
        let encoded = original.encode();
        assert_eq!(encoded.len(), original.encoded_len());
        assert_eq!(UdpMessage::decode(encoded), Some(original));
    }

    #[test]
    fn rejects_truncated() {
        let encoded = message(b"hello").encode();
        for cut in 0..FIXED_HEADER_LEN {
            assert_eq!(UdpMessage::decode(encoded.slice(..cut)), None);
        }
        // Заголовок целый, а адрес обрезан.
        assert_eq!(
            UdpMessage::decode(encoded.slice(..FIXED_HEADER_LEN + 2)),
            None
        );
    }

    #[test]
    fn whole_datagram_is_not_fragmented() {
        let parts =
            fragment(1, 1, "1.2.3.4:53", Bytes::from_static(b"short"), 1200).expect("влезает");
        assert_eq!(parts.len(), 1);
        assert!(parts[0].is_whole());
    }

    #[test]
    fn splits_and_reassembles() {
        let payload = Bytes::from(vec![7u8; 3000]);
        let parts = fragment(1, 42, "1.2.3.4:53", payload.clone(), 1200).expect("режется");
        assert!(parts.len() > 1);

        // Каждый фрагмент вместе с заголовком умещается в отведённый размер.
        for part in &parts {
            assert!(part.encoded_len() <= 1200, "фрагмент длиннее датаграммы");
            assert_eq!(part.fragment_count as usize, parts.len());
            assert_eq!(part.packet_id, 42);
        }

        let joined: Vec<u8> = parts.iter().flat_map(|p| p.payload.to_vec()).collect();
        assert_eq!(joined, payload.to_vec());
    }

    #[test]
    fn refuses_when_fragments_would_overflow_counter() {
        // Счётчик фрагментов однобайтовый; датаграмма, которой нужно больше,
        // не отправляется вовсе, а не режется до потери данных.
        let payload = Bytes::from(vec![0u8; 100_000]);
        assert_eq!(fragment(1, 1, "1.2.3.4:53", payload, 200), None);
    }

    #[test]
    fn refuses_when_header_does_not_fit() {
        let long_address = format!("{}:53", "a".repeat(300));
        assert_eq!(
            fragment(1, 1, &long_address, Bytes::from_static(b"x"), 100),
            None
        );
    }
}
