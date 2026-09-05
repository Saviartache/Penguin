//! Настоящая пара ключей для `key_share` — не байты для проформы.
//!
//! Отпечаток должен не только выглядеть правильно, но и работать: если
//! сервер решит, что перед ним не свой клиент, он пришлёт `ClientHello` дальше,
//! настоящему сайту, — и тот честно попробует довершить рукопожатие тем
//! самым ключом, который мы назвали в `key_share`. Случайные байты без
//! соответствующего закрытого ключа сделали бы такое рукопожатие
//! принципиально незавершимым: у нас не было бы скаляра, чтобы посчитать тот
//! же общий секрет, что и у сервера.
//!
//! Поэтому пара генерируется по-настоящему, через [`ring::agreement`] — тот
//! же провайдер, которым уже пользуется `penguin-transport`. Закрытый скаляр
//! наружу не отдаётся: `ring::agreement::EphemeralPrivateKey` устроен так,
//! что его нельзя ни клонировать, ни напечатать, ни экспортировать, — только
//! один раз применить в `agree_ephemeral`, когда придёт время. Это ровно та
//! степень секретности, которая нужна ключу, и `Debug` для нашей обёртки
//! унаследовал её бесплатно (`AGENTS.md` §5.2): у `EphemeralPrivateKey`
//! своего `Debug` попросту нет.
//!
//! Довести рукопожатие до конца — не дело этого крейта (см. документ
//! верхнего уровня): здесь закрытый ключ только рождается и передаётся
//! дальше, тому, кто год спустя прочитает `ServerHello` и позовёт
//! `ring::agreement::agree_ephemeral` сам.

use ring::agreement::{Algorithm, ECDH_P256, EphemeralPrivateKey, X25519};
use ring::rand::SecureRandom;

use crate::error::{UtlsError, UtlsResult};

/// Пара ключей одной группы `key_share`: публичные байты для провода и
/// закрытый ключ для будущего рукопожатия.
pub struct KeyExchange {
    /// Байты, которые идут в `key_share.data`: 32 байта для `X25519`, 65
    /// (несжатая точка, `0x04` + X + Y) для `P-256`.
    pub public: Vec<u8>,
    /// Закрытый ключ. Публичное поле — этот крейт рукопожатия не ведёт, и
    /// решать, когда и с каким `ServerHello.key_share` его свести, придётся
    /// тому, кто ведёт настоящее соединение.
    pub private: EphemeralPrivateKey,
}

impl std::fmt::Debug for KeyExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyExchange")
            .field("public_len", &self.public.len())
            .finish_non_exhaustive()
    }
}

/// Генерирует пару `X25519` — группа, которую предлагают все три отпечатка.
pub fn generate_x25519(rng: &dyn SecureRandom) -> UtlsResult<KeyExchange> {
    generate(&X25519, rng)
}

/// Генерирует пару `P-256` — вторая запись `key_share` у Firefox.
pub fn generate_p256(rng: &dyn SecureRandom) -> UtlsResult<KeyExchange> {
    generate(&ECDH_P256, rng)
}

fn generate(algorithm: &'static Algorithm, rng: &dyn SecureRandom) -> UtlsResult<KeyExchange> {
    let private = EphemeralPrivateKey::generate(algorithm, rng)
        .map_err(|_| UtlsError::KeyGeneration("генератор случайности недоступен"))?;
    let public = private
        .compute_public_key()
        .map_err(|_| UtlsError::KeyGeneration("не удалось вычислить публичный ключ"))?;
    Ok(KeyExchange {
        public: public.as_ref().to_vec(),
        private,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_keys_are_thirty_two_bytes() {
        let rng = ring::rand::SystemRandom::new();
        let pair = generate_x25519(&rng).expect("генерируется");
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
        let rng = ring::rand::SystemRandom::new();
        let first = generate_x25519(&rng).expect("генерируется");
        let second = generate_x25519(&rng).expect("генерируется");
        assert_ne!(first.public, second.public);
    }

    #[test]
    fn debug_does_not_print_the_private_key() {
        let rng = ring::rand::SystemRandom::new();
        let pair = generate_x25519(&rng).expect("генерируется");
        let printed = format!("{pair:?}");
        assert!(!printed.contains("EphemeralPrivateKey"));
        assert!(printed.contains("public_len"));
    }
}
