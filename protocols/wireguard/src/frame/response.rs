//! Сообщение рукопожатия «ответчик → инициатор» (тип 2).
//!
//! ```text
//! ┌──────┬────────┬────────────┬────────────┬───────────┬──────┬──────┐
//! │ тип  │ резерв │ отправитель│ получатель │ эфемерный │пустой│ mac1 │
//! │ (1)  │ (3)    │ (4)        │ (4)        │ (32)      │+тег  │ (16) │
//! │      │        │            │            │           │(16)  │      │
//! └──────┴────────┴────────────┴────────────┴───────────┴──────┴──────┘
//!                                                                + mac2 (16)
//! ```
//!
//! Итого 92 байта ([`RESPONSE_MESSAGE_LEN`]). Источник раскладки:
//! `MessageResponse` и его `marshal`/`unmarshal` в `device/noise-protocol.go`
//! (`wireguard-go`).
//!
//! Крейт это сообщение только разбирает — строит его сервер. `to_bytes` нет
//! по той же причине, по которой его нет для CookieReply: клиент отвечающей
//! стороной не бывает.

use crate::crypto::constants::{MESSAGE_RESPONSE, RESPONSE_MESSAGE_LEN};
use crate::error::{WireguardError, WireguardResult};

const OFF_TYPE: usize = 0;
const OFF_SENDER: usize = 4;
const OFF_RECEIVER: usize = 8;
const OFF_EPHEMERAL: usize = 12;
const OFF_EMPTY: usize = 44;
const OFF_MAC1: usize = 60;

const EPHEMERAL_LEN: usize = 32;
const EMPTY_CIPHERTEXT_LEN: usize = 16;

/// Поля, разобранные из сообщения ответа.
pub struct ResponseFields {
    /// Индекс, которым сервер будет опознавать себя как получателя пакетов
    /// данных.
    pub sender_index: u32,
    /// Индекс, который клиент выдал в сообщении инициации: сервер
    /// подтверждает, какому именно рукопожатию отвечает.
    pub receiver_index: u32,
    /// Открытый эфемерный ключ сервера.
    pub ephemeral_public: [u8; EPHEMERAL_LEN],
    /// Зашифрованная пустая строка — подтверждение транскрипта, а не данные.
    pub empty_ciphertext: [u8; EMPTY_CIPHERTEXT_LEN],
}

/// Байты, которые покрывает `mac1` сервера: сообщение до самого поля.
///
/// Считается тем же ключом, что и у клиента, только над статическим
/// открытым ключом клиента, а не сервера, — сообщение адресовано клиенту, и
/// метка защищает получателя от чужого трафика, а не отправителя.
pub fn mac1_covered(message: &[u8]) -> &[u8] {
    &message[..OFF_MAC1.min(message.len())]
}

/// Разбирает сообщение с провода.
///
/// Не проверяет ни `mac1`, ни расшифровку — только форму.
pub fn parse(bytes: &[u8]) -> WireguardResult<ResponseFields> {
    if bytes.len() != RESPONSE_MESSAGE_LEN {
        return Err(WireguardError::malformed(format!(
            "сообщение ответа длиной {} вместо {RESPONSE_MESSAGE_LEN}",
            bytes.len()
        )));
    }
    if bytes[OFF_TYPE] != MESSAGE_RESPONSE {
        return Err(WireguardError::malformed(format!(
            "тип сообщения {} вместо {MESSAGE_RESPONSE}",
            bytes[OFF_TYPE]
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

    /// Собирает сообщение вручную — эталон для тестов этого файла строит
    /// только сервер, и здесь у нас его нет.
    fn encode_for_test(fields: &ResponseFields) -> [u8; RESPONSE_MESSAGE_LEN] {
        let mut out = [0u8; RESPONSE_MESSAGE_LEN];
        out[OFF_TYPE] = MESSAGE_RESPONSE;
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
    fn the_wrong_message_type_is_rejected() {
        let mut encoded = encode_for_test(&sample());
        encoded[0] = 1;
        assert!(parse(&encoded).is_err());
    }
}
