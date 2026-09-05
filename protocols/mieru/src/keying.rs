//! Вывод сеансового ключа из имени пользователя, пароля и времени.
//!
//! Три шага, все — из `docs/protocol.md` эталона (ревизия `main`,
//! сентябрь 2026 года):
//!
//! 1. `hashedPassword = SHA256(password || 0x00 || username)`.
//! 2. `timeSalt = SHA256(BE64(round(unixTime, 2 минуты)))`.
//! 3. `key = PBKDF2-HMAC-SHA256(hashedPassword, timeSalt, 64 итерации, 32 байта)`.
//!
//! # Почему ключ зависит от времени
//!
//! Соль меняется каждые две минуты, и оба конца должны сойтись на одной и
//! той же соли, не обмениваясь ничем: сервер при расхождении часов пробует
//! соседние двухминутные окна, а клиент — нет, ему достаточно одного, своего.
//! Отсюда предел: часы не должны разойтись больше чем на четыре минуты —
//! иначе окно клиента не попадёт ни в одно из окон, которые пробует сервер.
//!
//! # Разбор

use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};

/// Сколько раз повторяется PBKDF2. Число из эталона, не выбор реализации:
/// не совпадёт — ключ выйдет другим, а несовпадение будет выглядеть
/// молчанием сервера, а не понятной ошибкой.
///
/// # Оно менялось между версиями
///
/// Здесь стоит значение третьей версии протокола. У второй было 4096, и
/// комментарий в эталоне это прямо говорит: «In mieru v2, the value was
/// 4096». Значит клиент **не подключится к серверу второй версии** — ключ
/// выйдет другим, и выглядеть это будет молчанием.
///
/// Поля версии в настройках у нас нет нарочно: вторая версия давно снята с
/// поддержки самим проектом, а поле, которое почти всегда имеет одно
/// значение, только уводит поиск неисправности в сторону. Если такие серверы
/// найдутся, поле заводится одной строкой — вместе с проверкой, что человек
/// понимает, что выбирает.
pub const PBKDF2_ITERATIONS: u32 = 64;

/// Длина сеансового ключа: XChaCha20-Poly1305 берёт 32 байта.
pub const KEY_LEN: usize = 32;

/// Окно округления времени в секундах — две минуты.
pub const TIME_WINDOW_SECS: i64 = 120;

/// Сеансовый ключ.
pub type Key = [u8; KEY_LEN];

/// Хэш пароля: пароль, разделитель `0x00`, имя пользователя.
///
/// Порядок важен и взят из эталона побайтно: пароль первым, а не имя, —
/// иначе один и тот же ключ вышел бы у пары пользователей с переставленными
/// именем и паролем.
pub fn hashed_password(username: &str, password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update([0u8]);
    hasher.update(username.as_bytes());
    hasher.finalize().into()
}

/// Соль, зависящая от текущего времени, округлённого до ближайших двух минут.
pub fn time_salt(unix_seconds: i64) -> [u8; 32] {
    let rounded = round_to_nearest(unix_seconds, TIME_WINDOW_SECS);
    // Отрицательным `rounded` в реальности не бывать — минимальный разумный
    // час давно позже 1970 года, — но привести к `u64` надо явно: эталон
    // пишет время как беззнаковое 64-битное число.
    let rounded = u64::try_from(rounded).unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(rounded.to_be_bytes());
    hasher.finalize().into()
}

/// Круглит к ближайшему кратному `step`, ровно посередине — от нуля прочь.
///
/// Так делает `time.Round` в эталоне. Расхождение здесь имело бы значение
/// только на секунду ровно посередине окна — исчезающе редкий случай,
/// который к тому же покрывает запас в четыре минуты общего допуска часов.
fn round_to_nearest(value: i64, step: i64) -> i64 {
    let half = step / 2;
    (value + half).div_euclid(step) * step
}

/// Выводит сеансовый ключ.
pub fn derive(username: &str, password: &str, unix_seconds: i64) -> Key {
    let hashed = hashed_password(username, password);
    let salt = time_salt(unix_seconds);
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(&hashed, &salt, PBKDF2_ITERATIONS, &mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Байты проверены независимым вычислением (SHA-256 и PBKDF2
    /// стандартной библиотеки .NET) — не круговым прогоном той же формулы.
    #[test]
    fn the_derivation_matches_an_independent_implementation() {
        let hashed = hashed_password("alice", "secret");
        assert_eq!(
            hashed,
            hex("67b378bdeeeb08cba0d9b00d6087d4b5873da34042df8d02a50a30d22982780c")
        );

        let salt = time_salt(1_700_000_000);
        assert_eq!(
            salt,
            hex("a93a74ae995047bb8ec3d7f2584a97d4bfffe25c81d83d19552e1bee60cda822")
        );

        let key = derive("alice", "secret", 1_700_000_000);
        assert_eq!(
            key,
            hex("5a6f31e64d069e26a69872e574c1fac00d5bad8595de4f01744b11ea596c315a")
        );
    }

    #[test]
    fn the_password_comes_before_the_username_in_the_hash() {
        // Переставленные местами имя и пароль обязаны дать другой хэш —
        // иначе аккаунт `("secret", "alice")` совпал бы с `("alice", "secret")`.
        assert_ne!(
            hashed_password("alice", "secret"),
            hashed_password("secret", "alice")
        );
    }

    #[test]
    fn the_salt_changes_every_two_minutes_and_not_more_often() {
        let base = 1_700_000_000_i64;
        let rounded = round_to_nearest(base, TIME_WINDOW_SECS);

        // Внутри одного двухминутного окна соль не меняется.
        assert_eq!(time_salt(rounded), time_salt(rounded + 59));
        // За его границей — меняется.
        assert_ne!(time_salt(rounded), time_salt(rounded + 61));
    }

    #[test]
    fn the_key_depends_on_all_three_inputs() {
        let base = derive("alice", "secret", 1_700_000_000);
        assert_ne!(base, derive("bob", "secret", 1_700_000_000));
        assert_ne!(base, derive("alice", "another", 1_700_000_000));
        assert_ne!(base, derive("alice", "secret", 1_700_000_400));
    }

    /// Разбирает шестнадцатеричную запись в массив байт фиксированной длины.
    fn hex<const N: usize>(text: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("тест содержит hex");
        }
        out
    }
}
