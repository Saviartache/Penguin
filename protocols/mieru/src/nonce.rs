//! Нонс XChaCha20-Poly1305: 24 байта, счётчик и подсказка имени пользователя.
//!
//! # Три операции
//!
//! - **Случайный нонс** заводит каждое направление соединения один раз.
//! - **Подсказка** заменяет последние 4 байта на первые 4 байта
//!   `SHA-256(username || nonce[..16])`. Она позволяет серверу быстро найти,
//!   каким пользователем расшифровывать сегмент, не перебирая ключи всех
//!   пользователей подряд, — сам нонс от этого секретнее не становится, он и
//!   так уходит на проводе открытым текстом.
//! - **Счётчик** прибавляет единицу к нонсу перед каждой следующей операцией
//!   AEAD в эту сторону. Прибавление идёт **с последнего байта**: перенос
//!   распространяется к первому. Порядок — из исходников эталона
//!   (`pkg/cipher/cipher.go`, функция `increaseNonce`), а не из описания: имея
//!   значение только в переносе через границу байта, он не виден почти
//!   никогда — и тем незаметнее ошибка при обратном порядке.

use sha2::{Digest, Sha256};

/// Длина нонса XChaCha20-Poly1305.
pub const LEN: usize = 24;

/// Сколько байт нонса входит в хэш подсказки.
pub const HINT_PREFIX: usize = 16;

/// Сколько байт нонса подсказка заменяет.
pub const HINT_SUFFIX: usize = 4;

/// Нонс.
pub type Nonce = [u8; LEN];

/// Случайный нонс.
pub fn random() -> Nonce {
    let mut nonce = [0u8; LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    nonce
}

/// Заменяет последние [`HINT_SUFFIX`] байт нонса подсказкой имени пользователя.
pub fn apply_hint(nonce: &mut Nonce, username: &str) {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update(&nonce[..HINT_PREFIX]);
    let hash = hasher.finalize();
    nonce[LEN - HINT_SUFFIX..].copy_from_slice(&hash[..HINT_SUFFIX]);
}

/// Прибавляет единицу к нонсу, считая его большим числом от последнего байта.
pub fn increment(nonce: &mut Nonce) {
    for byte in nonce.iter_mut().rev() {
        let (value, carry) = byte.overflowing_add(1);
        *byte = value;
        if !carry {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_random_nonces_are_not_the_same() {
        // Не доказательство случайности, но ловит самую грубую ошибку —
        // константный или нулевой нонс, при котором соединение расшифровать
        // может кто угодно, знающий ключ, а не только сеанс.
        assert_ne!(random(), random());
    }

    #[test]
    fn the_hint_matches_an_independent_sha256() {
        // Вычислено отдельно (см. доклад), не тем же кодом, что тестирует.
        let mut nonce = [0u8; LEN];
        for (i, byte) in nonce[..HINT_PREFIX].iter_mut().enumerate() {
            *byte = i as u8;
        }
        apply_hint(&mut nonce, "alice");
        assert_eq!(nonce[LEN - HINT_SUFFIX..], [0x4e, 0x3b, 0x9a, 0x70]);
    }

    #[test]
    fn the_hint_only_touches_the_last_four_bytes() {
        let mut nonce = [7u8; LEN];
        apply_hint(&mut nonce, "alice");
        assert_eq!(&nonce[..LEN - HINT_SUFFIX], &[7u8; LEN - HINT_SUFFIX]);
    }

    #[test]
    fn incrementing_carries_from_the_last_byte_towards_the_first() {
        // Обратный порядок — от первого байта — совпал бы с этим тестом на
        // первых 255 значениях и разошёлся бы дальше: соединение работало бы
        // и рвалось часами позже.
        let mut nonce = [0u8; LEN];
        increment(&mut nonce);
        assert_eq!(nonce[LEN - 1], 1, "единица легла не в последний байт");
        assert!(nonce[..LEN - 1].iter().all(|b| *b == 0));

        let mut nonce = [0u8; LEN];
        nonce[LEN - 1] = 0xff;
        increment(&mut nonce);
        assert_eq!(nonce[LEN - 1], 0, "перенос не случился");
        assert_eq!(nonce[LEN - 2], 1, "перенос ушёл не в предпоследний байт");
    }

    #[test]
    fn incrementing_wraps_without_panicking() {
        // Паника здесь оборвала бы тоннель, а не отдельное соединение
        // (`AGENTS.md` §4.3).
        let mut nonce = [0xff; LEN];
        increment(&mut nonce);
        assert_eq!(nonce, [0u8; LEN]);
    }
}
