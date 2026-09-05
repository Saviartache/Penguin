//! `EVP_BytesToKey` — вывод ключа из пароля так, как это делает OpenSSL.
//!
//! Здесь она общая, потому что её ждут два разных протокола и оба не вправе
//! её менять: Shadowsocks выводит ею главный ключ, ShadowsocksR — и главный
//! ключ, и отдельно ключ AES для разового заголовка `auth_aes128_*`.
//!
//! # Почему MD5 и почему это не наш выбор
//!
//! Функция гоняет MD5 по паролю без соли и без растяжения, то есть подбору
//! не мешает почти ничем. Заменить её на что-то разумное нельзя: так ключ
//! выводит **сервер**, и любая другая функция даст другой ключ и молчащее
//! соединение.
//!
//! Вывод из этого один и он для интерфейса: стойкость здесь держится на
//! длине пароля, а не на функции вывода. Короткий пароль означает короткий
//! ключ.
//!
//! # Про IV
//!
//! Настоящий OpenSSL считает этой же функцией ещё и IV — байты после
//! `key_len`-го. Ни один из наших протоколов их не берёт: у Shadowsocks
//! соль случайная на каждое соединение, у ShadowsocksR случайный IV. Поэтому
//! возвращается только ключ; первые `key_len` байт от длины IV не зависят
//! вовсе.

use md5::{Digest, Md5};

/// Пароль в ключ нужной длины.
///
/// Повторяет цикл OpenSSL с MD5 и одним проходом (`count=1`, без соли):
/// очередной блок — это MD5 от конкатенации предыдущего блока и пароля,
/// блоки копятся, пока не наберётся `key_len` байт.
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len + Md5::output_size());
    let mut previous: Vec<u8> = Vec::new();

    while key.len() < key_len {
        let mut digest = Md5::new();
        digest.update(&previous);
        digest.update(password);
        previous = digest.finalize().to_vec();
        key.extend_from_slice(&previous);
    }

    key.truncate(key_len);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Шестнадцатеричная запись — только для сверки с чужими значениями.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn matches_openssl_for_an_empty_password() {
        // `openssl enc -aes-256-cfb -k "" -P -md md5 -nosalt` — та же функция
        // в реализации, независимой и от Python, и от нас.
        let key = evp_bytes_to_key(b"", 32);
        assert_eq!(
            hex(&key),
            "d41d8cd98f00b204e9800998ecf8427e59adb24ef3cdbe0297f05b395827453f"
        );
    }

    #[test]
    fn matches_openssl_for_a_short_key() {
        // `openssl enc -aes-128-cfb -k "password" -P -md md5 -nosalt`.
        let key = evp_bytes_to_key(b"password", 16);
        assert_eq!(hex(&key), "5f4dcc3b5aa765d61d8327deb882cf99");
    }

    #[test]
    fn a_longer_request_continues_the_same_md5_chain() {
        // Первые 16 байт ключа на 32 и на 16 байт обязаны совпасть: это один
        // и тот же первый блок MD5, второй проход только достраивает хвост.
        let short = evp_bytes_to_key("пароль".as_bytes(), 16);
        let long = evp_bytes_to_key("пароль".as_bytes(), 32);
        assert_eq!(&long[..16], &short[..]);
    }

    #[test]
    fn the_key_depends_on_the_password() {
        let one = evp_bytes_to_key("один".as_bytes(), 16);
        let two = evp_bytes_to_key("два".as_bytes(), 16);
        assert_ne!(one, two);
    }

    #[test]
    fn a_key_shorter_than_one_md5_block_is_just_truncated() {
        let full = evp_bytes_to_key(b"password", 16);
        let short = evp_bytes_to_key(b"password", 8);
        assert_eq!(&full[..8], &short[..]);
    }
}
