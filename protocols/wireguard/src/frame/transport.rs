//! Пакет с данными (тип 4): заголовок плюс шифротекст ChaCha20-Poly1305.
//!
//! ```text
//! ┌──────┬────────┬────────────┬──────────┬─────────────────────────┐
//! │ тип  │ резерв │ получатель │ счётчик  │ шифротекст (+метка 16)  │
//! │ (1)  │ (3)    │ (4)        │ (8)      │ переменной длины        │
//! └──────┴────────┴────────────┴──────────┴─────────────────────────┘
//! ```
//!
//! Заголовок — 16 байт ([`TRANSPORT_HEADER_LEN`]), источник —
//! `MessageTransportHeaderSize` и раскладка `MessageTransport` в
//! `device/noise-protocol.go`. Пустой пакет-подтверждение (keepalive) —
//! это тот же формат с шифротекстом нулевой длины: 16 байт заголовка плюс
//! 16 байт одной метки Poly1305, и ни байта открытого текста.
//!
//! Счётчик — не индекс в потоке, а нонс AEAD для этого направления: значения
//! обязаны не повторяться, но необязаны идти подряд без пропусков (see
//! `crate::crypto::replay`).

use crate::crypto::constants::{MESSAGE_TRANSPORT_DATA, TRANSPORT_HEADER_LEN};
use crate::error::{WireguardError, WireguardResult};

const OFF_TYPE: usize = 0;
const OFF_RECEIVER: usize = 4;
const OFF_COUNTER: usize = 8;

/// Заголовок пакета с данными.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportHeader {
    /// Индекс сеанса на стороне получателя.
    pub receiver_index: u32,
    /// Счётчик-нонс этого пакета.
    pub counter: u64,
}

/// Собирает заголовок в готовые байты.
///
/// `reserved` — три байта после типа; см. `crate::config::WireguardConfig::reserved`.
pub fn encode_header(header: &TransportHeader, reserved: [u8; 3]) -> [u8; TRANSPORT_HEADER_LEN] {
    let mut out = [0u8; TRANSPORT_HEADER_LEN];
    out[OFF_TYPE] = MESSAGE_TRANSPORT_DATA;
    out[OFF_TYPE + 1..OFF_RECEIVER].copy_from_slice(&reserved);
    out[OFF_RECEIVER..OFF_COUNTER].copy_from_slice(&header.receiver_index.to_le_bytes());
    out[OFF_COUNTER..TRANSPORT_HEADER_LEN].copy_from_slice(&header.counter.to_le_bytes());
    out
}

/// Собирает целый пакет: заголовок плюс уже готовый шифротекст (с меткой).
pub fn build(header: &TransportHeader, reserved: [u8; 3], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(TRANSPORT_HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&encode_header(header, reserved));
    out.extend_from_slice(ciphertext);
    out
}

/// Разбирает заголовок и возвращает его вместе со срезом шифротекста,
/// который идёт следом.
///
/// Не проверяет содержимое шифротекста — это работа
/// `crate::crypto::session`, у которой есть ключ.
pub fn split(bytes: &[u8]) -> WireguardResult<(TransportHeader, &[u8])> {
    if bytes.len() < TRANSPORT_HEADER_LEN {
        return Err(WireguardError::malformed(format!(
            "пакет данных длиной {} короче заголовка в {TRANSPORT_HEADER_LEN}",
            bytes.len()
        )));
    }
    if bytes[OFF_TYPE] != MESSAGE_TRANSPORT_DATA {
        return Err(WireguardError::malformed(format!(
            "тип сообщения {} вместо {MESSAGE_TRANSPORT_DATA}",
            bytes[OFF_TYPE]
        )));
    }

    let mut receiver = [0u8; 4];
    receiver.copy_from_slice(&bytes[OFF_RECEIVER..OFF_COUNTER]);
    let mut counter = [0u8; 8];
    counter.copy_from_slice(&bytes[OFF_COUNTER..TRANSPORT_HEADER_LEN]);

    let header = TransportHeader {
        receiver_index: u32::from_le_bytes(receiver),
        counter: u64::from_le_bytes(counter),
    };
    Ok((header, &bytes[TRANSPORT_HEADER_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TransportHeader {
        TransportHeader {
            receiver_index: 0xDEAD_BEEF,
            counter: 0x0102_0304_0506_0708,
        }
    }

    #[test]
    fn the_header_is_exactly_sixteen_bytes() {
        let encoded = encode_header(&sample(), [0, 0, 0]);
        assert_eq!(encoded.len(), TRANSPORT_HEADER_LEN);
    }

    #[test]
    fn the_receiver_index_and_counter_are_little_endian() {
        let encoded = encode_header(&sample(), [0, 0, 0]);
        assert_eq!(&encoded[4..8], &0xDEAD_BEEFu32.to_le_bytes());
        assert_eq!(&encoded[8..16], &0x0102_0304_0506_0708u64.to_le_bytes());
    }

    #[test]
    fn round_trip_through_build_and_split_preserves_the_header_and_the_ciphertext() {
        let header = sample();
        let ciphertext = [1, 2, 3, 4, 5];
        let packet = build(&header, [0, 0, 0], &ciphertext);
        let (parsed, remaining) = split(&packet).expect("разбирается");
        assert_eq!(parsed, header);
        assert_eq!(remaining, ciphertext);
    }

    #[test]
    fn a_keepalive_is_a_header_with_no_content_before_the_tag() {
        // Само подтверждение — пустой открытый текст; шифротекст здесь уже с
        // меткой, поэтому даже "пустой" keepalive несёт 16 байт тега.
        let packet = build(&sample(), [0, 0, 0], &[0u8; 16]);
        assert_eq!(packet.len(), TRANSPORT_HEADER_LEN + 16);
    }

    #[test]
    fn reserved_bytes_land_right_after_the_type_byte() {
        let encoded = encode_header(&sample(), [0xAA, 0xBB, 0xCC]);
        assert_eq!(encoded[0], MESSAGE_TRANSPORT_DATA);
        assert_eq!(&encoded[1..4], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn a_packet_shorter_than_the_header_is_rejected() {
        assert!(split(&[4, 0, 0, 0]).is_err());
    }

    #[test]
    fn the_wrong_message_type_is_rejected() {
        let mut packet = build(&sample(), [0, 0, 0], &[]);
        packet[0] = 1;
        assert!(split(&packet).is_err());
    }
}
