//! Размешивание ключа для `rc4-md5` и вывод главного ключа из пароля.
//!
//! ```text
//!  пароль ──EVP_BytesToKey(MD5)──► главный ключ
//!  (для rc4-md5: ключ шифра = MD5(главный ключ || IV соединения))
//! ```
//!
//! Сам `EVP_BytesToKey` лежит в [`penguin_transport::kdf`] — его ждёт ещё и
//! Shadowsocks, а здесь он зовётся дважды: за главным ключом и ещё раз,
//! с другой строкой вместо пароля, — за ключом AES разового заголовка
//! `auth_aes128_*` (см. [`crate::protocol`]).
//!
//! # Откуда берётся IV, если не отсюда
//!
//! IV на запись — **случайные байты, свои на каждое соединение**, точно как
//! соль у Shadowsocks; выводит их [`crate::outbound`]. IV на чтение — то, что
//! первым прислал сервер. `EVP_BytesToKey` в эталоне (`Encryptor.get_cipher`
//! в `shadowsocks/encrypt.py`) считает попутно и IV — но тут же его
//! выбрасывает: настоящий IV соединения берётся не из него.
//!
//! # Разбор

use md5::{Digest, Md5};
pub use penguin_transport::kdf::evp_bytes_to_key;

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
