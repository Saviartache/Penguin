//! Инициация (тип 1), 148 байт ([`INITIATION_MESSAGE_LEN`]): тип 1, резерв 3,
//! отправитель 4, эфемерный 32, статический+метка 48, время+метка 28, mac1 16, mac2 16
//! (`MessageInitiation` в `device/noise-protocol.go`). Только раскладка;
//! MAC считает `crate::crypto::handshake`.

use crate::crypto::constants::INITIATION_MESSAGE_LEN;
use crate::crypto::constants::MESSAGE_INITIATION;
use crate::error::{WireguardError, WireguardResult};

/// Длина заголовка: тип и три резервных байта вместе (магический заголовок AmneziaWG).
const HEADER_LEN: usize = 4;

const OFF_TYPE: usize = 0;
const OFF_SENDER: usize = 4;
const OFF_EPHEMERAL: usize = 8;
const OFF_STATIC: usize = 40;
const OFF_TIMESTAMP: usize = 88;
const OFF_MAC1: usize = 116;
const OFF_MAC2: usize = 132;

const EPHEMERAL_LEN: usize = 32;
const STATIC_CIPHERTEXT_LEN: usize = 48;
const TIMESTAMP_CIPHERTEXT_LEN: usize = 28;
const MAC_LEN: usize = 16;

/// Поля сообщения, готовые лечь на провод.
pub struct InitiationFields {
    /// Случайный индекс отправителя.
    pub sender_index: u32,
    /// Открытый эфемерный ключ этого рукопожатия.
    pub ephemeral_public: [u8; EPHEMERAL_LEN],
    /// Собственный статический открытый ключ, зашифрованный для ответчика.
    pub static_ciphertext: [u8; STATIC_CIPHERTEXT_LEN],
    /// Метка времени TAI64N, зашифрованная для ответчика.
    pub timestamp_ciphertext: [u8; TIMESTAMP_CIPHERTEXT_LEN],
}

/// Собирает сообщение без `mac1` ([`set_mac1`]); `mac2` остаётся нулём.
/// `header` - первые 4 байта: в обычном WireGuard `[тип, резерв…]`, в AmneziaWG
/// магический заголовок `H1` целиком. Он входит под `mac1`, поэтому ставится здесь.
pub fn encode(fields: &InitiationFields, header: [u8; HEADER_LEN]) -> [u8; INITIATION_MESSAGE_LEN] {
    let mut out = [0u8; INITIATION_MESSAGE_LEN];
    out[OFF_TYPE..OFF_SENDER].copy_from_slice(&header);
    out[OFF_SENDER..OFF_EPHEMERAL].copy_from_slice(&fields.sender_index.to_le_bytes());
    out[OFF_EPHEMERAL..OFF_STATIC].copy_from_slice(&fields.ephemeral_public);
    out[OFF_STATIC..OFF_TIMESTAMP].copy_from_slice(&fields.static_ciphertext);
    out[OFF_TIMESTAMP..OFF_MAC1].copy_from_slice(&fields.timestamp_ciphertext);
    out
}

/// Байты, которые покрывает `mac1`: всё сообщение до самого поля.
pub fn mac1_covered(message: &[u8; INITIATION_MESSAGE_LEN]) -> &[u8] {
    &message[..OFF_MAC1]
}

/// Байты, которые покрывает `mac2`: сообщение вместе с уже вписанным `mac1`.
pub fn mac2_covered(message: &[u8; INITIATION_MESSAGE_LEN]) -> &[u8] {
    &message[..OFF_MAC2]
}

/// Вписывает посчитанный `mac1` в готовое место.
pub fn set_mac1(message: &mut [u8; INITIATION_MESSAGE_LEN], mac1: [u8; MAC_LEN]) {
    message[OFF_MAC1..OFF_MAC2].copy_from_slice(&mac1);
}

/// Разбирает сообщение с провода, проверяя только форму.
pub fn parse(bytes: &[u8]) -> WireguardResult<InitiationFields> {
    if bytes.len() != INITIATION_MESSAGE_LEN {
        return Err(WireguardError::malformed(format!(
            "сообщение инициации длиной {} вместо {INITIATION_MESSAGE_LEN}",
            bytes.len()
        )));
    }
    if bytes[OFF_TYPE] != MESSAGE_INITIATION {
        return Err(WireguardError::malformed(format!(
            "тип сообщения {} вместо {MESSAGE_INITIATION}",
            bytes[OFF_TYPE]
        )));
    }

    let mut sender = [0u8; 4];
    sender.copy_from_slice(&bytes[OFF_SENDER..OFF_EPHEMERAL]);
    let mut ephemeral_public = [0u8; EPHEMERAL_LEN];
    ephemeral_public.copy_from_slice(&bytes[OFF_EPHEMERAL..OFF_STATIC]);
    let mut static_ciphertext = [0u8; STATIC_CIPHERTEXT_LEN];
    static_ciphertext.copy_from_slice(&bytes[OFF_STATIC..OFF_TIMESTAMP]);
    let mut timestamp_ciphertext = [0u8; TIMESTAMP_CIPHERTEXT_LEN];
    timestamp_ciphertext.copy_from_slice(&bytes[OFF_TIMESTAMP..OFF_MAC1]);

    Ok(InitiationFields {
        sender_index: u32::from_le_bytes(sender),
        ephemeral_public,
        static_ciphertext,
        timestamp_ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> InitiationFields {
        InitiationFields {
            sender_index: 0xAABB_CCDD,
            ephemeral_public: [7u8; EPHEMERAL_LEN],
            static_ciphertext: [9u8; STATIC_CIPHERTEXT_LEN],
            timestamp_ciphertext: [3u8; TIMESTAMP_CIPHERTEXT_LEN],
        }
    }

    #[test]
    fn the_encoded_message_has_the_exact_wire_length() {
        let encoded = encode(&sample(), [MESSAGE_INITIATION, 0, 0, 0]);
        assert_eq!(encoded.len(), INITIATION_MESSAGE_LEN);
    }

    #[test]
    fn the_type_byte_is_first_and_reserved_bytes_follow_it() {
        let encoded = encode(&sample(), [MESSAGE_INITIATION, 0xAA, 0xBB, 0xCC]);
        assert_eq!(encoded[0], MESSAGE_INITIATION);
        assert_eq!(&encoded[1..4], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn the_sender_index_is_little_endian() {
        let encoded = encode(&sample(), [MESSAGE_INITIATION, 0, 0, 0]);
        assert_eq!(&encoded[4..8], &0xAABB_CCDDu32.to_le_bytes());
    }

    #[test]
    fn round_trip_through_encode_and_parse_preserves_every_field() {
        let fields = sample();
        let encoded = encode(&fields, [MESSAGE_INITIATION, 0, 0, 0]);
        let parsed = parse(&encoded).expect("разбирается");
        assert_eq!(parsed.sender_index, fields.sender_index);
        assert_eq!(parsed.ephemeral_public, fields.ephemeral_public);
        assert_eq!(parsed.static_ciphertext, fields.static_ciphertext);
        assert_eq!(parsed.timestamp_ciphertext, fields.timestamp_ciphertext);
    }

    #[test]
    fn mac_ranges_cover_exactly_what_the_spec_says_they_cover() {
        let encoded = encode(&sample(), [MESSAGE_INITIATION, 0, 0, 0]);
        assert_eq!(mac1_covered(&encoded).len(), 116);
        assert_eq!(mac2_covered(&encoded).len(), 132);
    }

    #[test]
    fn setting_mac1_does_not_disturb_the_rest_of_the_message() {
        let mut encoded = encode(&sample(), [MESSAGE_INITIATION, 0, 0, 0]);
        let before = mac1_covered(&encoded).to_vec();
        set_mac1(&mut encoded, [0xEE; MAC_LEN]);
        assert_eq!(mac1_covered(&encoded), before.as_slice());
        assert_eq!(&encoded[116..132], &[0xEE; MAC_LEN]);
        assert_eq!(&encoded[132..148], &[0u8; MAC_LEN]);
    }

    #[test]
    fn a_short_message_is_rejected() {
        assert!(parse(&[0u8; 10]).is_err());
    }

    #[test]
    fn the_wrong_message_type_is_rejected() {
        let mut encoded = encode(&sample(), [MESSAGE_INITIATION, 0, 0, 0]);
        encoded[0] = 2;
        assert!(parse(&encoded).is_err());
    }
}
