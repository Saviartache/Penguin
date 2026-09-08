//! Ключи одного соединения: то общее, что нужно и заголовку, и телу.
//!
//! Заголовок запроса везёт `requestBodyKey`/`requestBodyIV` в открытый
//! (для нас) вид — сервер получает их расшифровкой заголовка. Ключи ответа
//! из них не копируются, а выводятся: первые 16 байт `SHA-256` от каждого
//! (`proxy/vmess/encoding/client.go`, `NewClientSession`, ветка `isAEAD`,
//! эталон `v2fly/v2ray-core`, `master`). Значит, оба конца требуют одного и
//! того же вывода, не обмениваясь лишним сообщением.

use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::crypto::security::Wire;

/// Ключи и служебные байты одного TCP- или UDP-потока.
pub struct Session {
    /// Шифр тела, уже приведённый к тому, что едет на провод.
    pub wire: Wire,
    /// Ключ тела в запросе — уходит серверу внутри заголовка.
    pub request_body_key: [u8; 16],
    /// `IV` тела в запросе — туда же.
    pub request_body_iv: [u8; 16],
    /// Ключ тела в ответе — выводится, а не передаётся.
    pub response_body_key: [u8; 16],
    /// `IV` тела в ответе — тоже выводится.
    pub response_body_iv: [u8; 16],
    /// Байт, который сервер обязан вернуть первым байтом расшифрованного
    /// заголовка ответа. Несовпадение — [`crate::error::VmessError::AuthRejected`].
    pub response_header: u8,
}

impl Session {
    /// Заводит новую сессию: случайные ключ и `IV` тела, случайный байт
    /// проверки, выведенные из них ключи ответа.
    pub fn new(wire: Wire) -> Self {
        let mut rng = rand::thread_rng();
        let mut request_body_key = [0u8; 16];
        let mut request_body_iv = [0u8; 16];
        rng.fill_bytes(&mut request_body_key);
        rng.fill_bytes(&mut request_body_iv);
        let mut response_header = [0u8; 1];
        rng.fill_bytes(&mut response_header);

        Self {
            wire,
            response_body_key: sha256_16(&request_body_key),
            response_body_iv: sha256_16(&request_body_iv),
            request_body_key,
            request_body_iv,
            response_header: response_header[0],
        }
    }
}

/// Первые 16 байт `SHA-256` — так эталон выводит оба ключа ответа.
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
