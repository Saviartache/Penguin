//! Настоящие пары ключей для `key_share`: рукопожатие можно довести до конца.
//!
//! `P-256` — `ring::agreement` (одно применение). `X25519` — `StaticSecret`:
//! Reality считает общий секрет с одним скаляром дважды (ключ Reality и ключ
//! сервера), `agree_ephemeral` для этого не годится.

use ring::agreement::{Algorithm, ECDH_P256, EphemeralPrivateKey};
use ring::rand::SecureRandom;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

use crate::error::{UtlsError, UtlsResult};

enum Private {
    X25519(X25519Secret),
    P256(EphemeralPrivateKey),
}

/// Пара ключей одной группы `key_share`: публичные байты для провода и
/// закрытый ключ для будущего рукопожатия.
pub struct KeyExchange {
    /// Байты, которые идут в `key_share.data`: 32 байта для `X25519`, 65
    /// (несжатая точка, `0x04` + X + Y) для `P-256`.
    pub public: Vec<u8>,
    private: Private,
}

impl std::fmt::Debug for KeyExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyExchange")
            .field("public_len", &self.public.len())
            .finish_non_exhaustive()
    }
}

impl KeyExchange {
    /// Сырой общий секрет `X25519` (RFC 7748); `None` для не-`X25519`. Ключ не потребляется.
    pub fn x25519_diffie_hellman(&self, peer_public: &[u8; 32]) -> Option<[u8; 32]> {
        match &self.private {
            Private::X25519(secret) => {
                let peer = X25519PublicKey::from(*peer_public);
                Some(*secret.diffie_hellman(&peer).as_bytes())
            }
            Private::P256(_) => None,
        }
    }

    /// Отдаёт закрытый ключ `P-256`; `None` для `X25519`.
    pub fn into_p256_private(self) -> Option<EphemeralPrivateKey> {
        match self.private {
            Private::P256(key) => Some(key),
            Private::X25519(_) => None,
        }
    }
}

/// Генерирует пару `X25519` (единственная группа Reality).
pub fn generate_x25519() -> KeyExchange {
    let private = X25519Secret::from(penguin_proto::random::array::<32>());
    let public = X25519PublicKey::from(&private);
    KeyExchange {
        public: public.as_bytes().to_vec(),
        private: Private::X25519(private),
    }
}

/// Генерирует пару `P-256` — вторая запись `key_share` у Firefox.
pub fn generate_p256(rng: &dyn SecureRandom) -> UtlsResult<KeyExchange> {
    generate_p256_with(&ECDH_P256, rng)
}

fn generate_p256_with(
    algorithm: &'static Algorithm,
    rng: &dyn SecureRandom,
) -> UtlsResult<KeyExchange> {
    let private = EphemeralPrivateKey::generate(algorithm, rng)
        .map_err(|_| UtlsError::KeyGeneration("генератор случайности недоступен"))?;
    let public = private
        .compute_public_key()
        .map_err(|_| UtlsError::KeyGeneration("не удалось вычислить публичный ключ"))?;
    Ok(KeyExchange {
        public: public.as_ref().to_vec(),
        private: Private::P256(private),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_keys_are_thirty_two_bytes() {
        let pair = generate_x25519();
        assert_eq!(pair.public.len(), 32);
    }

    #[test]
    fn p256_keys_are_uncompressed_points() {
        let rng = ring::rand::SystemRandom::new();
        let pair = generate_p256(&rng).expect("генерируется");
        // 0x04, потом X и Y по 32 байта — несжатая точка, RFC 8446 §4.2.8.1.
        assert_eq!(pair.public.len(), 65);
        assert_eq!(pair.public[0], 0x04);
    }

    #[test]
    fn two_generated_keys_are_not_the_same() {
        let first = generate_x25519();
        let second = generate_x25519();
        assert_ne!(first.public, second.public);
    }

    #[test]
    fn debug_does_not_print_the_private_key() {
        let pair = generate_x25519();
        let printed = format!("{pair:?}");
        assert!(!printed.contains("StaticSecret"));
        assert!(printed.contains("public_len"));
    }

    #[test]
    fn p256_keys_do_not_support_x25519_diffie_hellman() {
        let rng = ring::rand::SystemRandom::new();
        let pair = generate_p256(&rng).expect("генерируется");
        assert!(pair.x25519_diffie_hellman(&[0; 32]).is_none());
    }

    #[test]
    fn only_p256_keys_hand_over_their_private_key() {
        let rng = ring::rand::SystemRandom::new();
        assert!(
            generate_p256(&rng)
                .expect("генерируется")
                .into_p256_private()
                .is_some()
        );
        assert!(generate_x25519().into_p256_private().is_none());
    }

    /// Общий секрет X25519, вектор из RFC 8448 §3 ("Simple 1-RTT Handshake"):
    /// закрытый ключ клиента и публичный ключ сервера из настоящей трассы
    /// TLS 1.3 дают ровно тот `IKM`, который RFC печатает на шаге "{server}
    /// extract secret \"handshake\"". Это не наш формат (Reality здесь ни при
    /// чём), а прямая проверка, что `x25519_dalek` в этой обвязке считает
    /// стандартный `X25519()`, а не что-то похожее на него.
    #[test]
    fn x25519_diffie_hellman_matches_the_rfc_8448_test_vector() {
        let client_private: [u8; 32] = [
            0x49, 0xaf, 0x42, 0xba, 0x7f, 0x79, 0x94, 0x85, 0x2d, 0x71, 0x3e, 0xf2, 0x78, 0x4b,
            0xcb, 0xca, 0xa7, 0x91, 0x1d, 0xe2, 0x6a, 0xdc, 0x56, 0x42, 0xcb, 0x63, 0x45, 0x40,
            0xe7, 0xea, 0x50, 0x05,
        ];
        let server_public: [u8; 32] = [
            0xc9, 0x82, 0x88, 0x76, 0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb, 0xf7, 0xc6,
            0x72, 0xe1, 0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1, 0xb0,
            0x4e, 0x75, 0x1f, 0x0f,
        ];
        let expected: [u8; 32] = [
            0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63, 0xfd, 0xfb, 0xac, 0xf9, 0xf0, 0x4b,
            0x9f, 0x0d, 0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75, 0x63, 0xef, 0xd4, 0x62, 0x72, 0x90,
            0x0f, 0x89, 0x49, 0x2d,
        ];

        let pair = KeyExchange {
            public: Vec::new(),
            private: Private::X25519(X25519Secret::from(client_private)),
        };
        let shared = pair
            .x25519_diffie_hellman(&server_public)
            .expect("это X25519");
        assert_eq!(shared, expected);
    }
}
