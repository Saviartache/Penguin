//! Вывод главного ключа: `EVP_BytesToKey` из пароля, и отдельно —
//! размешивание ключа для `rc4-md5`.
//!
//! ```text
//!  пароль ──EVP_BytesToKey(MD5)──► главный ключ
//!  (для rc4-md5: ключ шифра = MD5(главный ключ || IV соединения))
//! ```
//!
//! # Откуда берётся IV, если не отсюда
//!
//! IV на запись — **случайные байты, свои на каждое соединение**, точно как
//! соль у Shadowsocks; выводит их [`crate::outbound`], а не эта функция. IV
//! на чтение — то, что первым прислал сервер, он читается с провода
//! (`crate::stream`). `EVP_BytesToKey` в эталоне (`Encryptor.get_cipher` в
//! `shadowsocks/encrypt.py`) действительно считает попутно ещё и IV — но тут
//! же его выбрасывает: тот же вызов, что даёт ключ, отдаёт и IV, только
//! настоящий IV соединения берётся не из него, а из отдельного параметра.
//! Поэтому здесь эта функция возвращает только ключ — второй результат
//! эталона нигде и никогда не используется, ни в этом крейте, ни в нём
//! самом.
//!
//! # Почему `EVP_BytesToKey`, а не что-то новее
//!
//! Как и у Shadowsocks: так ключ выводит **сервер**, и заменить это на
//! что-то разумное — значит подключаться под другим ключом, то есть не
//! подключаться вовсе. Подробный разбор той же функции — в
//! `penguin_shadowsocks::crypto::kdf`; здесь она переписана самостоятельно,
//! потому что там она возвращает только ключ (Shadowsocks — сплошь AEAD,
//! IV/соль там всегда случайные и никогда не выводятся из пароля), а SSR
//! использует тот же вызов ещё раз — с другой строкой вместо пароля — для
//! ключа AES разового заголовка `auth_aes128_*` (см.
//! `crate::protocol::auth_aes128`).
//!
//! Проверено по эталону дважды: значение ключа ниже совпадает с тем, что
//! печатает `openssl enc -k <пароль> -P -md md5 -nosalt` — та самая функция
//! в независимой от Python и от Rust реализации.

use md5::{Digest, Md5};

/// `EVP_BytesToKey`: пароль в ключ нужной длины.
///
/// Повторяет цикл OpenSSL с MD5 и одним проходом (`count=1`, без соли):
/// очередной блок — это MD5 от конкатенации предыдущего блока и пароля,
/// блоки копятся, пока не наберётся `key_len` байт. Байты после `key_len`-го
/// эталон тоже считает (там, где ему нужен ещё и IV), но не они делают ключ
/// длиннее — первые `key_len` байт от `iv_len` не зависят вовсе.
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len + Md5::output_size());
    let mut prev: Vec<u8> = Vec::new();

    while out.len() < key_len {
        let mut digest = Md5::new();
        digest.update(&prev);
        digest.update(password);
        prev = digest.finalize().to_vec();
        out.extend_from_slice(&prev);
    }

    out.truncate(key_len);
    out
}

/// Ключ RC4 для метода `rc4-md5`: `MD5(главный_ключ || IV_соединения)`.
///
/// IV здесь используется не как параметр шифра (у RC4 его нет), а как
/// добавка, из-за которой одному паролю на разных соединениях соответствуют
/// разные ключи RC4. Защита слабая — один проход MD5, никакого растяжения, —
/// но это протокол SSR, а не наш выбор.
pub fn rc4_md5_key(master_key: &[u8], iv: &[u8]) -> [u8; 16] {
    let mut digest = Md5::new();
    digest.update(master_key);
    digest.update(iv);
    digest.finalize().into()
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
        // `openssl enc -aes-256-cfb -k "" -P -md md5 -nosalt`:
        //   key=D41D8CD98F00B204E9800998ECF8427E59ADB24EF3CDBE0297F05B395827453
        let key = evp_bytes_to_key(b"", 32);
        assert_eq!(
            hex(&key),
            "d41d8cd98f00b204e9800998ecf8427e59adb24ef3cdbe0297f05b395827453f"
        );
    }

    #[test]
    fn matches_openssl_for_a_short_key() {
        // `openssl enc -aes-128-cfb -k "password" -P -md md5 -nosalt`:
        //   key=5F4DCC3B5AA765D61D8327DEB882CF99
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
    fn rc4_md5_key_matches_the_reference_value() {
        // master взят из `matches_openssl_for_a_short_key`-подобного вызова
        // для пароля "secret password" (aes-128-cfb, 16 байт ключа); iv —
        // произвольные 16 байт, тоже сверенные с независимым источником
        // (`openssl enc -aes-128-cfb -k "secret password" -P -md md5 -nosalt`
        // печатает тот же IV, хоть здесь он и не с этой ролью). Сам результат
        // смешивания — из отдельного прогона `openssl md5` по конкатенации
        // их сырых байт.
        let master = evp_bytes_to_key(b"secret password", 16);
        assert_eq!(hex(&master), "a584efafa8f9ea7fe5cf18442f32b07b");

        let iv = [
            0xdf, 0x68, 0x12, 0xc2, 0xba, 0x4d, 0xbf, 0x17, 0x9e, 0xee, 0xb1, 0x6e, 0xd1, 0x83,
            0x49, 0x44,
        ];
        let rc4_key = rc4_md5_key(&master, &iv);
        assert_eq!(hex(&rc4_key), "5a9027a2f22620899ad2ee33e578dd2a");
    }

    #[test]
    fn rc4_md5_key_changes_with_the_iv() {
        // Иначе каждое соединение шифровалось бы одним и тем же ключом RC4,
        // и повтор ключевого потока раскрывает оба сообщения.
        let master = evp_bytes_to_key("пароль".as_bytes(), 16);
        let first = rc4_md5_key(&master, &[1u8; 16]);
        let second = rc4_md5_key(&master, &[2u8; 16]);
        assert_ne!(first, second);
    }
}
