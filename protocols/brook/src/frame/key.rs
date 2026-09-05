//! Вывод ключа: HKDF-SHA256 прямо из пароля, без главного ключа.
//!
//! ```text
//!  пароль ──┐
//!           ├── HKDF-SHA256(соль=нонс, метка="brook") ──► ключ AES-256, 32 байта
//!  нонс ────┘   (12 случайных байт, свои у каждого направления)
//! ```
//!
//! Соль — не что-то отдельное от нонса: это те же двенадцать байт, которые
//! уходят собеседнику открытым текстом и потом сами служат первым значением
//! счётчика (см. [`crate::frame::nonce`]). Одно и то же значение отвечает за
//! обе вещи, и назвать их разными словами значило бы спрятать эту связь.
//!
//! Метка — литерал `[0x62, 0x72, 0x6f, 0x6f, 0x6b]`, то есть ASCII `brook`.
//! У эталона (`init.go`) она задаётся двумя переменными, `ClientHKDFInfo` и
//! `ServerHKDFInfo`, но обе по умолчанию равны одному и тому же значению;
//! расходятся они только если сервер настроен нестандартно (флаги
//! `--clientHKDFInfo`/`--serverHKDFInfo` у `brook link`). Эта настройка сюда
//! не перенесена: она меняет самих себя так, что клиент и сервер обязаны
//! сговориться заранее, а профиль обычного пользователя такого не делает.

use ring::hkdf;

use crate::error::{BrookError, BrookResult};
use crate::frame::nonce::Nonce;

/// Длина ключа AES-256.
pub const KEY_LEN: usize = 32;

/// Метка HKDF. ASCII `brook`, тот же литерал, каким его пишет эталон.
const INFO: &[u8] = &[0x62, 0x72, 0x6f, 0x6f, 0x6b];

/// Выводит ключ направления из пароля и нонса этого направления.
pub fn derive(password: &[u8], nonce: &Nonce) -> BrookResult<[u8; KEY_LEN]> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, nonce);
    let material = salt.extract(password);

    let output = material
        .expand(&[INFO], KeyLen)
        .map_err(|_| BrookError::crypto("не выводится ключ"))?;

    let mut key = [0u8; KEY_LEN];
    output
        .fill(&mut key)
        .map_err(|_| BrookError::crypto("не выводится ключ"))?;
    Ok(key)
}

/// Длина вывода для HKDF: `ring` требует её типом, а не числом.
#[derive(Debug, Clone, Copy)]
struct KeyLen;

impl hkdf::KeyType for KeyLen {
    fn len(&self) -> usize {
        KEY_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::nonce::NONCE_LEN;

    fn nonce(mark: u8) -> Nonce {
        [mark; NONCE_LEN]
    }

    #[test]
    fn the_label_is_the_ascii_word_brook() {
        // Опечатка в метке даёт другой ключ и молчащий сервер — то есть
        // поломку, которую по симптому не отличить от неверного пароля.
        assert_eq!(INFO, "brook".as_bytes());
    }

    #[test]
    fn the_key_is_the_length_aes_256_wants() {
        let key = derive(b"secret", &nonce(1)).expect("выводится");
        assert_eq!(key.len(), KEY_LEN);
    }

    #[test]
    fn the_nonce_and_the_password_both_change_the_key() {
        let base = derive(b"secret", &nonce(1)).expect("выводится");
        let other_nonce = derive(b"secret", &nonce(2)).expect("выводится");
        let other_password = derive("другой".as_bytes(), &nonce(1)).expect("выводится");

        assert_ne!(base, other_nonce, "нонс не участвует");
        assert_ne!(base, other_password, "пароль не участвует");
    }

    #[test]
    fn the_same_input_gives_the_same_key() {
        // Иначе клиент и сервер разошлись бы на первом же кадре.
        assert_eq!(
            derive(b"secret", &nonce(7)).expect("выводится"),
            derive(b"secret", &nonce(7)).expect("выводится")
        );
    }

    #[test]
    fn client_and_server_nonces_give_independent_keys() {
        // Клиент выводит ключ на отправку из своего нонса, сервер — на
        // отправку из своего; общего секрета между двумя ключами быть не
        // должно, иначе перепутать направления было бы легко.
        let client = derive(b"secret", &nonce(1)).expect("выводится");
        let server = derive(b"secret", &nonce(2)).expect("выводится");
        assert_ne!(client, server);
    }
}
