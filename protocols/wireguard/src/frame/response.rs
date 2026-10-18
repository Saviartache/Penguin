//! Ответ (тип 2), 92 байта ([`RESPONSE_MESSAGE_LEN`]): тип 1, резерв 3, отправитель 4,
//! получатель 4, эфемерный 32, пустой+метка 16, mac1 16, mac2 16
//! (`MessageResponse` в `device/noise-protocol.go`). Только разбор: строит его сервер.
//!
//! Первые 4 байта не проверяются: в AmneziaWG там магический заголовок `H2`,
//! а не тип 2. Класс сообщения определяет вызывающий (по типу или через
//! `crate::obfs`), а `mac1` сервер считает поверх этих байт как есть.

use crate::crypto::constants::RESPONSE_MESSAGE_LEN;
use crate::error::{WireguardError, WireguardResult};

const OFF_SENDER: usize = 4;
const OFF_RECEIVER: usize = 8;
const OFF_EPHEMERAL: usize = 12;
const OFF_EMPTY: usize = 44;
const OFF_MAC1: usize = 60;

const EPHEMERAL_LEN: usize = 32;
const EMPTY_CIPHERTEXT_LEN: usize = 16;

/// Поля, разобранные из сообщения ответа.
pub struct ResponseFields {
    /// Индекс сервера.
    pub sender_index: u32,
    /// Индекс клиента из инициации.
    pub receiver_index: u32,
    /// Открытый эфемерный ключ сервера.
    pub ephemeral_public: [u8; EPHEMERAL_LEN],
    /// Зашифрованная пустая строка (подтверждение транскрипта).
    pub empty_ciphertext: [u8; EMPTY_CIPHERTEXT_LEN],
}

/// Байты, которые покрывает `mac1`: сообщение до самого поля.
pub fn mac1_covered(message: &[u8]) -> &[u8] {
    &message[..OFF_MAC1.min(message.len())]
}

/// Разбирает сообщение с провода, проверяя только форму.
pub fn parse(bytes: &[u8]) -> WireguardResult<ResponseFields> {
    if bytes.len() != RESPONSE_MESSAGE_LEN {
        return Err(WireguardError::malformed(format!(
            "сообщение ответа длиной {} вместо {RESPONSE_MESSAGE_LEN}",
            bytes.len()
        )));
    }

    let mut sender = [0u8; 4];
    sender.copy_from_slice(&bytes[OFF_SENDER..OFF_RECEIVER]);
    let mut receiver = [0u8; 4];
    receiver.copy_from_slice(&bytes[OFF_RECEIVER..OFF_EPHEMERAL]);
    let mut ephemeral_public = [0u8; EPHEMERAL_LEN];
    ephemeral_public.copy_from_slice(&bytes[OFF_EPHEMERAL..OFF_EMPTY]);
    let mut empty_ciphertext = [0u8; EMPTY_CIPHERTEXT_LEN];
    empty_ciphertext.copy_from_slice(&bytes[OFF_EMPTY..OFF_MAC1]);

    Ok(ResponseFields {
        sender_index: u32::from_le_bytes(sender),
        receiver_index: u32::from_le_bytes(receiver),
        ephemeral_public,
        empty_ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::constants::MESSAGE_RESPONSE;

    /// Сборка только для тестов: строит ответ сервер.
    fn encode_for_test(fields: &ResponseFields) -> [u8; RESPONSE_MESSAGE_LEN] {
        let mut out = [0u8; RESPONSE_MESSAGE_LEN];
        out[0] = MESSAGE_RESPONSE;
        out[OFF_SENDER..OFF_RECEIVER].copy_from_slice(&fields.sender_index.to_le_bytes());
        out[OFF_RECEIVER..OFF_EPHEMERAL].copy_from_slice(&fields.receiver_index.to_le_bytes());
        out[OFF_EPHEMERAL..OFF_EMPTY].copy_from_slice(&fields.ephemeral_public);
        out[OFF_EMPTY..OFF_MAC1].copy_from_slice(&fields.empty_ciphertext);
        out
    }

    fn sample() -> ResponseFields {
        ResponseFields {
            sender_index: 0x1122_3344,
            receiver_index: 0x5566_7788,
            ephemeral_public: [5u8; EPHEMERAL_LEN],
            empty_ciphertext: [8u8; EMPTY_CIPHERTEXT_LEN],
        }
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let fields = sample();
        let encoded = encode_for_test(&fields);
        let parsed = parse(&encoded).expect("разбирается");
        assert_eq!(parsed.sender_index, fields.sender_index);
        assert_eq!(parsed.receiver_index, fields.receiver_index);
        assert_eq!(parsed.ephemeral_public, fields.ephemeral_public);
        assert_eq!(parsed.empty_ciphertext, fields.empty_ciphertext);
    }

    #[test]
    fn mac1_covers_exactly_sixty_bytes() {
        let encoded = encode_for_test(&sample());
        assert_eq!(mac1_covered(&encoded).len(), 60);
    }

    #[test]
    fn a_short_message_is_rejected() {
        assert!(parse(&[0u8; 10]).is_err());
    }

    #[test]
    fn an_amneziawg_magic_header_in_the_first_four_bytes_is_accepted() {
        // В AmneziaWG первые 4 байта - заголовок `H2`, а не тип 2; разбор смотрит
        // только на длину, поля читаются по фиксированным смещениям.
        let mut encoded = encode_for_test(&sample());
        encoded[0..4].copy_from_slice(&0x7D21_93FEu32.to_le_bytes());
        let parsed = parse(&encoded).expect("разбирается несмотря на магический заголовок");
        assert_eq!(parsed.sender_index, sample().sender_index);
    }
}
