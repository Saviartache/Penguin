//! Настоящая пара ключей для `key_share` — не байты для проформы.
//!
//! Отпечаток должен не только выглядеть правильно, но и работать: если
//! сервер решит, что перед ним не свой клиент, он пришлёт `ClientHello`
//! дальше, настоящему сайту, — и тот честно попробует довершить рукопожатие
//! тем самым ключом, который мы назвали в `key_share`. Случайные байты без
//! соответствующего закрытого ключа сделали бы такое рукопожатие
//! принципиально незавершимым: у нас не было бы скаляра, чтобы посчитать тот
//! же общий секрет, что и у сервера.
//!
//! # Почему `X25519` и `P-256` устроены по-разному
//!
//! `P-256` считается через [`ring::agreement`] — тот же провайдер, которым
//! уже пользуется `penguin-transport`. `ring::agreement::EphemeralPrivateKey`
//! устроен так, что его нельзя ни клонировать, ни напечатать, ни
//! экспортировать — только один раз применить в `agree_ephemeral`. Для
//! обычного TLS это ровно та степень секретности, которая нужна: скаляр
//! рукопожатия участвует в одном согласовании ключа и после этого не нужен.
//!
//! У `X25519` спрос другой: Reality считает общий секрет с этим же скаляром
//! **дважды** — один раз с публичным ключом Reality (данные опознания в
//! `SessionID`), другой раз с настоящим ключом сервера из `ServerHello`
//! (собственно TLS 1.3). `agree_ephemeral` для второго вызова уже не
//! годится — ключ потрачен первым же согласованием. Поэтому `X25519` держит
//! [`x25519_dalek::StaticSecret`] — тот же тип и по той же причине, что уже
//! взял `protocols/wireguard` (`crypto/handshake.rs`: там один эфемерный
//! ключ Noise IK тоже участвует в двух разных `DH` за одно рукопожатие).
//! `StaticSecret` не завязан на однократное использование и не отдаёт байты
//! скаляра наружу ни при каких обстоятельствах — секретность та же, метод
//! другой.

use ring::agreement::{Algorithm, ECDH_P256, EphemeralPrivateKey};
use ring::rand::SecureRandom;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

use crate::error::{UtlsError, UtlsResult};

/// Закрытая половина пары — по одному варианту на группу, потому что только
/// `X25519` поддерживает повторное согласование (см. документ модуля).
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
    /// Общий секрет `X25519` с чужим публичным значением (сырой результат
    /// RFC 7748 `X25519()`, без последующего хеширования).
    ///
    /// `None`, если эта пара — не `X25519` (например, `P-256` у Firefox):
    /// Reality всегда использует `X25519` — конфигурация `xray-core` и
    /// `sing-box` не принимает для неё другой группы, — а звать этот метод
    /// имеет смысл только ради Reality.
    ///
    /// В отличие от [`ring::agreement::agree_ephemeral`] метод не потребляет
    /// ключ и может быть вызван снова с другим чужим значением — см. документ
    /// модуля о том, зачем это Reality нужно дважды.
    pub fn x25519_diffie_hellman(&self, peer_public: &[u8; 32]) -> Option<[u8; 32]> {
        match &self.private {
            Private::X25519(secret) => {
                let peer = X25519PublicKey::from(*peer_public);
                Some(*secret.diffie_hellman(&peer).as_bytes())
            }
            Private::P256(_) => None,
        }
    }

    /// Отдаёт закрытый ключ `P-256` тому, кто поведёт настоящее рукопожатие
    /// дальше. `None`, если эта пара — `X25519`.
    ///
    /// Пара расходуется: `ring::agreement::EphemeralPrivateKey` годится
    /// только на одно применение (`agree_ephemeral`), и делить его на «дать
    /// посмотреть» и «дать использовать» бессмысленно — как и у `X25519`,
    /// Reality эта группа не нужна вовсе (`x25519_diffie_hellman`), метод
    /// существует ради того самого гипотетического настоящего сайта, которому
    /// Reality перешлёт `ClientHello`, если не узнает клиента.
    pub fn into_p256_private(self) -> Option<EphemeralPrivateKey> {
        match self.private {
            Private::P256(key) => Some(key),
            Private::X25519(_) => None,
        }
    }
}

/// Генерирует пару `X25519` — группа, которую предлагают все три отпечатка,
/// и единственная, которую понимает Reality.
pub fn generate_x25519() -> KeyExchange {
    let private = X25519Secret::random();
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
