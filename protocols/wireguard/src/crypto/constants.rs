//! Константы протокола: часть договора с сервером, а не выбор реализации.
//! Источники - `wireguard-go` (`device/constants.go`, `noise-helpers.go`,
//! `noise-protocol.go`) и `boringtun`; сверка в `crate::crypto::primitives`.

use std::time::Duration;

/// Имя конструкции Noise (`wireguard.com/protocol/`, `NoiseConstruction`).
pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// Идентификатор протокола (`WGIdentifier`).
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

/// Метка ключа `mac1` (`WGLabelMAC1`).
pub const LABEL_MAC1: &[u8] = b"mac1----";

/// Метка ключа cookie (`WGLabelCookie`); cookie-ответы не разбираются.
pub const LABEL_COOKIE: &[u8] = b"cookie--";

/// Тип сообщения: инициация.
pub const MESSAGE_INITIATION: u8 = 1;
/// Тип сообщения: ответ на инициацию.
pub const MESSAGE_RESPONSE: u8 = 2;
/// Тип сообщения: cookie-ответ сервера под нагрузкой (не поддерживается).
pub const MESSAGE_COOKIE_REPLY: u8 = 3;
/// Тип сообщения: пакет данных.
pub const MESSAGE_TRANSPORT_DATA: u8 = 4;

/// Длина ключа X25519 и общего секрета.
pub const KEY_LEN: usize = 32;
/// Длина метки ChaCha20-Poly1305.
pub const AEAD_TAG_LEN: usize = 16;
/// Длина `mac1`/`mac2`.
pub const MAC_LEN: usize = 16;
/// Длина метки времени TAI64N.
pub const TIMESTAMP_LEN: usize = 12;

/// Размер инициации (`MessageInitiationSize`).
pub const INITIATION_MESSAGE_LEN: usize = 148;

/// Размер ответа (`MessageResponseSize`).
pub const RESPONSE_MESSAGE_LEN: usize = 92;

/// Размер заголовка пакета данных (`MessageTransportHeaderSize`).
pub const TRANSPORT_HEADER_LEN: usize = 16;

/// MTU: 1500 минус IPv6 (40), UDP (8), заголовок WireGuard (16) и метка (16);
/// см. `PacketInterface::mtu`.
pub const DEFAULT_MTU: u16 = 1420;

/// Порог сообщений для обновления рукопожатия (`RekeyAfterMessages`).
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;

/// Предел счётчика сеанса, `(1 << 64) - (1 << 13) - 1` (`RejectAfterMessages`).
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

const _: () = assert!(REKEY_AFTER_MESSAGES < REJECT_AFTER_MESSAGES);
const _: () = assert!(REJECT_AFTER_MESSAGES < u64::MAX);

/// Через сколько обновлять рукопожатие (`RekeyAfterTime`).
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);

/// Срок жизни сеанса (`RejectAfterTime`).
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

/// Ожидание ответа на инициацию (`RekeyTimeout`).
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);

/// Разброс повтора, `[0, 334)` мс (`RekeyTimeoutJitterMaxMs`).
pub const REKEY_TIMEOUT_JITTER_MAX_MS: u64 = 334;

/// Сколько пытаться провести рукопожатие (`RekeyAttemptTime`).
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);

/// Молчание, после которого уходит пустой пакет (`KeepaliveTimeout`).
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// `PersistentKeepalive` по умолчанию (`man 8 wg`).
pub const DEFAULT_KEEPALIVE_SECS: u32 = 25;

/// Наибольший `PersistentKeepalive` (`man 8 wg`).
pub const MAX_KEEPALIVE_SECS: u32 = 65535;

/// Ширина окна повторов, в пакетах: локальная политика, как у `boringtun`.
pub const REPLAY_WINDOW_BITS: u64 = 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_construction_string_is_the_exact_length_it_claims() {
        assert_eq!(CONSTRUCTION.len(), 37);
        assert_eq!(IDENTIFIER.len(), 34);
        assert_eq!(LABEL_MAC1.len(), 8);
        assert_eq!(LABEL_COOKIE.len(), 8);
    }

    #[test]
    fn message_type_bytes_match_the_wire_format() {
        assert_eq!(MESSAGE_INITIATION, 1);
        assert_eq!(MESSAGE_RESPONSE, 2);
        assert_eq!(MESSAGE_COOKIE_REPLY, 3);
        assert_eq!(MESSAGE_TRANSPORT_DATA, 4);
    }

    #[test]
    fn message_sizes_add_up_field_by_field() {
        assert_eq!(4 + 4 + 32 + 48 + 28 + 16 + 16, INITIATION_MESSAGE_LEN);
        assert_eq!(4 + 4 + 4 + 32 + 16 + 16 + 16, RESPONSE_MESSAGE_LEN);
        assert_eq!(4 + 4 + 8, TRANSPORT_HEADER_LEN);
    }

    #[test]
    fn the_message_counter_limit_matches_the_reference_formula() {
        // В `u128`, чтобы формула проверки не совпала с кодом через то же переполнение.
        let reference: u128 = (1u128 << 64) - (1u128 << 13) - 1;
        assert_eq!(u128::from(REJECT_AFTER_MESSAGES), reference);
    }

    #[test]
    fn the_rekey_timeout_is_shorter_than_the_attempt_window() {
        assert!(REKEY_TIMEOUT < REKEY_ATTEMPT_TIME);
    }

    #[test]
    fn the_mtu_leaves_the_headroom_the_packet_contract_documents() {
        assert_eq!(1500 - DEFAULT_MTU, 80);
    }
}
