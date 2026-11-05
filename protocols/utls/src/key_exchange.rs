//! Настоящие пары ключей для `key_share`: рукопожатие можно довести до конца.
//!
//! `X25519` — `StaticSecret`: Reality считает общий секрет с одним скаляром дважды
//! (ключ Reality и ключ сервера). `X25519MLKEM768` — `ml-kem` и свой X25519.
//!
//! Других групп нет: сервер REALITY повторяет только `X25519` и `X25519MLKEM768`
//! (`XTLS/REALITY` `tls.go`), на любую другую из `key_share` он отдаёт сайт-прикрытие.

use ml_kem::{Ciphertext, Decapsulate, DecapsulationKey768, KeyExport, MlKem768, Seed};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

/// Группа `X25519` (RFC 8446 §4.2.7).
pub const GROUP_X25519: u16 = 29;
/// Группа `P-256` (RFC 8446 §4.2.7): только в `supported_groups`, ключа нет.
pub const GROUP_P256: u16 = 23;
/// Гибрид `X25519MLKEM768` (uTLS `common.go`, draft-ietf-tls-ecdhe-mlkem).
pub const GROUP_X25519_MLKEM768: u16 = 4588;

/// Длина шифротекста ML-KEM-768 в `key_share` сервера (FIPS 203).
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

enum Private {
    X25519(X25519Secret),
    /// Свой X25519, не общий с записью `X25519` (uTLS `mlkemEcdhe`, как у Chrome).
    X25519Mlkem768 {
        mlkem: Box<DecapsulationKey768>,
        x25519: X25519Secret,
    },
}

/// Пара ключей одной группы `key_share`: публичные байты для провода и
/// закрытый ключ для будущего рукопожатия.
pub struct KeyExchange {
    /// Группа записи `key_share`.
    pub group: u16,
    /// Байты, которые идут в `key_share.data`: 32 байта для `X25519`, ключ ML-KEM ‖ X25519
    /// для гибрида.
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
            Private::X25519(secret) => Some(x25519(secret, peer_public)),
            Private::X25519Mlkem768 { .. } => None,
        }
    }

    /// Общий секрет TLS 1.3 с `key_share` сервера той же группы: у гибрида ML-KEM ‖ X25519
    /// (uTLS `handshake_client_tls13.go`). `None` — неверный ключ сервера.
    pub fn agree(self, server_share: &[u8]) -> Option<Vec<u8>> {
        match self.private {
            Private::X25519(secret) => {
                Some(x25519(&secret, server_share.try_into().ok()?).to_vec())
            }
            Private::X25519Mlkem768 {
                mlkem,
                x25519: secret,
            } => {
                if server_share.len() != MLKEM768_CIPHERTEXT_LEN + 32 {
                    return None;
                }
                let (ciphertext, peer) = server_share.split_at(MLKEM768_CIPHERTEXT_LEN);
                let ciphertext = Ciphertext::<MlKem768>::try_from(ciphertext).ok()?;
                let mut shared = mlkem.decapsulate(&ciphertext).to_vec();
                shared.extend_from_slice(&x25519(&secret, peer.try_into().ok()?));
                Some(shared)
            }
        }
    }

    /// Запись `X25519` на X25519 гибрида (uTLS `ReuseHybridAndClassicalKeyShares`, Firefox);
    /// `None` не для гибрида.
    pub fn reused_x25519(&self) -> Option<KeyExchange> {
        let Private::X25519Mlkem768 { x25519, .. } = &self.private else {
            return None;
        };
        Some(KeyExchange {
            group: GROUP_X25519,
            public: self.public[self.public.len() - 32..].to_vec(),
            private: Private::X25519(x25519.clone()),
        })
    }
}

fn x25519(secret: &X25519Secret, peer_public: &[u8; 32]) -> [u8; 32] {
    *secret
        .diffie_hellman(&X25519PublicKey::from(*peer_public))
        .as_bytes()
}

/// Генерирует пару `X25519` (Reality опознаёт клиента по ней).
pub fn generate_x25519() -> KeyExchange {
    let private = X25519Secret::from(penguin_proto::random::array::<32>());
    let public = X25519PublicKey::from(&private);
    KeyExchange {
        group: GROUP_X25519,
        public: public.as_bytes().to_vec(),
        private: Private::X25519(private),
    }
}

/// Генерирует пару `X25519MLKEM768`: ключ ML-KEM-768 из 64 байт затравки (FIPS 203 `d ‖ z`,
/// как `mlkem.NewDecapsulationKey768` у uTLS) и свой X25519.
pub fn generate_x25519_mlkem768() -> KeyExchange {
    let mlkem = DecapsulationKey768::from_seed(Seed::from(penguin_proto::random::array::<64>()));
    let x25519 = X25519Secret::from(penguin_proto::random::array::<32>());
    let mut public = mlkem.encapsulation_key().to_bytes().to_vec();
    public.extend_from_slice(X25519PublicKey::from(&x25519).as_bytes());
    KeyExchange {
        group: GROUP_X25519_MLKEM768,
        public,
        private: Private::X25519Mlkem768 {
            mlkem: Box::new(mlkem),
            x25519,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_keys_are_thirty_two_bytes() {
        let pair = generate_x25519();
        assert_eq!(pair.public.len(), 32);
    }

    /// Без внешнего вектора: сервер — `encapsulate_deterministic` того же `ml-kem` (его KAT
    /// FIPS 203 — в самом крейте); проверяются раскладка ключа и порядок ML-KEM ‖ X25519.
    #[test]
    fn the_hybrid_secret_is_mlkem_then_x25519() {
        use ml_kem::EncapsulationKey768;
        use ml_kem::array::Array;

        let client = generate_x25519_mlkem768();
        assert_eq!(client.public.len(), 1184 + 32);
        let (mlkem_public, x25519_public) = client.public.split_at(1184);

        let ek = EncapsulationKey768::new(&Array::try_from(mlkem_public).expect("1184 байта"))
            .expect("ключ ML-KEM верен");
        let (ciphertext, mlkem_shared) = ek.encapsulate_deterministic(&Array::from([7u8; 32]));
        let server = X25519Secret::from([9u8; 32]);
        let x25519_shared = x25519(&server, x25519_public.try_into().expect("32 байта"));

        let mut share = ciphertext.to_vec();
        share.extend_from_slice(X25519PublicKey::from(&server).as_bytes());
        let mut expected = mlkem_shared.to_vec();
        expected.extend_from_slice(&x25519_shared);

        assert!(client.x25519_diffie_hellman(&[0; 32]).is_none());
        let reused = client.reused_x25519().expect("гибрид");
        assert_eq!(reused.public, x25519_public);
        let server_public = X25519PublicKey::from(&server).to_bytes();
        assert_eq!(
            reused.x25519_diffie_hellman(&server_public),
            Some(x25519_shared)
        );
        assert!(reused.reused_x25519().is_none());

        assert_eq!(client.agree(&share), Some(expected));
        assert_eq!(
            generate_x25519_mlkem768().agree(&share[1..]),
            None,
            "длина проверяется"
        );
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
            group: GROUP_X25519,
            public: Vec::new(),
            private: Private::X25519(X25519Secret::from(client_private)),
        };
        let shared = pair
            .x25519_diffie_hellman(&server_public)
            .expect("это X25519");
        assert_eq!(shared, expected);
    }
}
