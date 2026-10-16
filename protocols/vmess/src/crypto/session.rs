//! Ключи одного соединения, общие для заголовка и тела.

use penguin_proto::random;
use sha2::{Digest, Sha256};

use crate::crypto::security::Wire;

/// Ключи и служебные байты одного TCP- или UDP-потока.
pub struct Session {
    /// Шифр тела, приведённый к тому, что едет на провод.
    pub wire: Wire,
    /// Ключ тела в запросе; уходит серверу в заголовке.
    pub request_body_key: [u8; 16],
    /// `IV` тела в запросе.
    pub request_body_iv: [u8; 16],
    /// Ключ тела в ответе; выводится, не передаётся.
    pub response_body_key: [u8; 16],
    /// `IV` тела в ответе; выводится.
    pub response_body_iv: [u8; 16],
    /// Первый байт расшифрованного заголовка ответа; иначе `AuthRejected`.
    pub response_header: u8,
}

impl Session {
    /// Новая сессия: случайные ключ, `IV` и байт проверки, ключи ответа выведены.
    pub fn new(wire: Wire) -> Self {
        let request_body_key = random::array();
        let request_body_iv = random::array();
        let [response_header] = random::array();
        Self {
            wire,
            response_body_key: sha256_16(&request_body_key),
            response_body_iv: sha256_16(&request_body_iv),
            request_body_key,
            request_body_iv,
            response_header,
        }
    }
}

/// Первые 16 байт `SHA-256`: так выводятся ключи ответа
/// (`proxy/vmess/encoding/client.go`, `NewClientSession`, `v2fly/v2ray-core`).
fn sha256_16(input: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(input);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_keys_are_derived_not_random() {
        let session = Session::new(Wire::Aes128Gcm);
        assert_eq!(
            session.response_body_key,
            sha256_16(&session.request_body_key)
        );
        assert_eq!(
            session.response_body_iv,
            sha256_16(&session.request_body_iv)
        );
    }

    #[test]
    fn two_sessions_do_not_share_keys() {
        let a = Session::new(Wire::Aes128Gcm);
        let b = Session::new(Wire::Aes128Gcm);
        assert_ne!(a.request_body_key, b.request_body_key);
        assert_ne!(a.request_body_iv, b.request_body_iv);
    }
}
