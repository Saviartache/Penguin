//! Вывод ключей: из пароля — главный ключ, из главного и соли — сеансовый.
//!
//! ```text
//!  пароль ──EVP_BytesToKey──► главный ключ ──┐
//!                                            ├─HKDF-SHA1──► сеансовый ключ
//!  соль (случайная, на каждое соединение) ───┘
//! ```
//!
//! # Почему MD5 и почему это не наш выбор
//!
//! `EVP_BytesToKey` — старая функция из OpenSSL: она гоняет MD5 по паролю без
//! соли и без растяжения, то есть подбору не мешает почти ничем. Заменить её
//! на что-то разумное нельзя: так ключ выводит **сервер**, и любая другая
//! функция даст другой ключ и молчащее соединение.
//!
//! Вывод из этого один и он для интерфейса: у Shadowsocks стойкость держится
//! на длине пароля, а не на функции вывода. Короткий пароль здесь означает
//! короткий ключ.
//!
//! # Зачем ещё и HKDF
//!
//! Главный ключ один на все соединения. Шифровать им напрямую значило бы
//! повторять пару «ключ, счётчик» в каждом новом соединении, а для AEAD это
//! полный провал: два разных сообщения под одной парой раскрывают оба.
//!
//! Поэтому на каждое соединение бросается случайная соль, она уходит первой,
//! открытым текстом, и вместе с главным ключом даёт сеансовый.

use md5::{Digest, Md5};
use ring::hkdf;

use crate::crypto::method::Method;
use crate::error::{ShadowsocksError, ShadowsocksResult};

/// Метка, под которой протокол выводит сеансовый ключ.
///
/// Часть договора с сервером: другая метка — другой ключ.
const INFO: &[u8] = b"ss-subkey";

/// Главный ключ из пароля.
///
/// Повторяет `EVP_BytesToKey` из OpenSSL с MD5 и одним проходом: MD5 от
/// предыдущего куска и пароля, пока не наберётся нужная длина.
pub fn master_key(password: &str, method: Method) -> Vec<u8> {
    let want = method.key_len();
    let mut key = Vec::with_capacity(want + Md5::output_size());
    let mut previous = Vec::new();

    while key.len() < want {
        let mut digest = Md5::new();
        digest.update(&previous);
        digest.update(password.as_bytes());
        previous = digest.finalize().to_vec();
        key.extend_from_slice(&previous);
    }

    key.truncate(want);
    key
}

/// Сеансовый ключ из главного и соли.
pub fn session_key(master: &[u8], salt: &[u8], method: Method) -> ShadowsocksResult<Vec<u8>> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt);
    let material = salt.extract(master);

    let length = KeyLen(method.key_len());
    let output = material
        .expand(&[INFO], length)
        .map_err(|_| ShadowsocksError::crypto("не выводится сеансовый ключ"))?;

    let mut key = vec![0u8; method.key_len()];
    output
        .fill(&mut key)
        .map_err(|_| ShadowsocksError::crypto("не выводится сеансовый ключ"))?;
    Ok(key)
}

/// Длина вывода для HKDF: `ring` требует её типом, а не числом.
#[derive(Debug, Clone, Copy)]
struct KeyLen(usize);

impl hkdf::KeyType for KeyLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Шестнадцатеричная запись — только для сверки с чужими значениями.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn the_master_key_matches_the_known_answer() {
        // `EVP_BytesToKey` от пустого пароля — это просто MD5 от пустой
        // строки. Проверяется о чужой ответ: своя реализация согласится сама
        // с собой при любой ошибке в порядке склейки.
        let key = master_key("", Method::Aes128Gcm);
        assert_eq!(hex(&key), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn a_longer_key_continues_the_same_chain() {
        // Тридцать два байта — это два прохода MD5, и первые шестнадцать
        // обязаны совпасть с ключом на шестнадцать.
        let short = master_key("пароль", Method::Aes128Gcm);
        let long = master_key("пароль", Method::Aes256Gcm);

        assert_eq!(short.len(), 16);
        assert_eq!(long.len(), 32);
        assert_eq!(&long[..16], &short[..]);
    }

    #[test]
    fn the_key_depends_on_the_password() {
        assert_ne!(
            master_key("один", Method::Aes256Gcm),
            master_key("два", Method::Aes256Gcm)
        );
    }

    #[test]
    fn the_session_key_changes_with_the_salt() {
        // Иначе каждое соединение шифровалось бы одной парой «ключ, счётчик»,
        // а для AEAD это раскрывает оба сообщения.
        let master = master_key("пароль", Method::Aes256Gcm);
        let first = session_key(&master, &[1u8; 32], Method::Aes256Gcm).expect("выводится");
        let second = session_key(&master, &[2u8; 32], Method::Aes256Gcm).expect("выводится");

        assert_ne!(first, second);
        assert_eq!(first.len(), 32);
    }

    #[test]
    fn the_same_salt_gives_the_same_key() {
        // Иначе сервер и клиент не сошлись бы никогда.
        let master = master_key("пароль", Method::Aes128Gcm);
        let salt = [7u8; 16];
        assert_eq!(
            session_key(&master, &salt, Method::Aes128Gcm).expect("выводится"),
            session_key(&master, &salt, Method::Aes128Gcm).expect("выводится")
        );
    }

    #[test]
    fn the_label_is_the_one_the_protocol_names() {
        // Записанного вектора для сеансового ключа здесь нет намеренно.
        // Взять его неоткуда: посчитать самим значит проверить реализацию её
        // же выводом, а такой тест проходит и тогда, когда всё сломано.
        //
        // Сам HKDF считает `ring`, ему верим. Наше здесь — три вещи: метка,
        // длина и то, что соль вообще участвует. Метка — часть договора с
        // сервером, и опечатка в ней даёт молчащее соединение.
        assert_eq!(INFO, b"ss-subkey");
    }
}
