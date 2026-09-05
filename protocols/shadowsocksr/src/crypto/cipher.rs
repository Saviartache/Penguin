//! Сами потоковые шифры: построение из ключа и IV, применение к байтам.
//!
//! Шифрование и расшифровка у CFB — разные операции (обратная связь идёт по
//! шифротексту), поэтому направление выбирается на постройке
//! (`build_encryptor` / `build_decryptor`), а дальше обе стороны видны
//! потребителю (`crate::stream`) одинаково — через `Keystream`.
//!
//! У CTR и RC4 шифрование и расшифровка — одна и та же операция (XOR с
//! ключевым потоком), но отдельные конструкторы всё равно нужны: ключ RC4
//! для `rc4-md5` зависит от направления ровно так же мало, как и всё
//! остальное здесь, — а вот структура вызова со стороны `stream` должна
//! быть одной и той же для всех методов.

use aes::cipher::{BlockCipherEncrypt, KeyInit, KeyIvInit, StreamCipher as _};
use aes::{Aes128, Aes192, Aes256};
use cfb_mode::{BufDecryptor, BufEncryptor};
use ctr::Ctr128BE;
use rc4::Rc4;

use crate::crypto::kdf;
use crate::crypto::method::Method;
use crate::error::{ShadowsocksrError, ShadowsocksrResult};

/// Однонаправленный шифр: применяет ключевой поток к байтам на месте.
///
/// Для CFB это шифрование или расшифровка (выбраны при постройке), для CTR,
/// RC4 и `none` — одна и та же операция в обе стороны.
pub(crate) trait Keystream: Send {
    /// Накладывает ключевой поток на `data`, продолжая с того места, на
    /// котором остановился прошлый вызов.
    fn apply(&mut self, data: &mut [u8]);
}

/// Метод `none`: ключевого потока нет, байты не меняются.
struct NoCipher;

impl Keystream for NoCipher {
    fn apply(&mut self, _data: &mut [u8]) {}
}

impl Keystream for Rc4 {
    fn apply(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }
}

impl Keystream for Ctr128BE<Aes128> {
    fn apply(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }
}

impl Keystream for Ctr128BE<Aes192> {
    fn apply(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }
}

impl Keystream for Ctr128BE<Aes256> {
    fn apply(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }
}

impl<C: BlockCipherEncrypt + Send> Keystream for BufEncryptor<C> {
    fn apply(&mut self, data: &mut [u8]) {
        self.encrypt(data);
    }
}

impl<C: BlockCipherEncrypt + Send> Keystream for BufDecryptor<C> {
    fn apply(&mut self, data: &mut [u8]) {
        self.decrypt(data);
    }
}

/// Заворачивает ошибку неверной длины ключа/IV в ошибку крейта.
///
/// Длины уже проверены таблицей [`Method`], так что на практике этот путь
/// означает ошибку в самой таблице, а не в настройках пользователя.
fn bad_length<E: std::fmt::Display>(err: E) -> ShadowsocksrError {
    ShadowsocksrError::crypto(format!("неверная длина ключа или IV: {err}"))
}

/// Строит шифр для направления «зашифровать».
pub(crate) fn build_encryptor(
    method: Method,
    master_key: &[u8],
    iv: &[u8],
) -> ShadowsocksrResult<Box<dyn Keystream>> {
    match method {
        Method::None => Ok(Box::new(NoCipher)),
        Method::Rc4Md5 => {
            let key = kdf::rc4_md5_key(master_key, iv);
            Ok(Box::new(Rc4::new_from_slice(&key).map_err(bad_length)?))
        }
        Method::Aes128Cfb => Ok(Box::new(
            BufEncryptor::<Aes128>::new_from_slices(master_key, iv).map_err(bad_length)?,
        )),
        Method::Aes192Cfb => Ok(Box::new(
            BufEncryptor::<Aes192>::new_from_slices(master_key, iv).map_err(bad_length)?,
        )),
        Method::Aes256Cfb => Ok(Box::new(
            BufEncryptor::<Aes256>::new_from_slices(master_key, iv).map_err(bad_length)?,
        )),
        Method::Aes128Ctr => Ok(Box::new(
            Ctr128BE::<Aes128>::new_from_slices(master_key, iv).map_err(bad_length)?,
        )),
        Method::Aes192Ctr => Ok(Box::new(
            Ctr128BE::<Aes192>::new_from_slices(master_key, iv).map_err(bad_length)?,
        )),
        Method::Aes256Ctr => Ok(Box::new(
            Ctr128BE::<Aes256>::new_from_slices(master_key, iv).map_err(bad_length)?,
        )),
    }
}

/// Строит шифр для направления «расшифровать».
///
/// Для CTR, RC4 и `none` совпадает по коду с [`build_encryptor`] — операция
/// та же самая, — но остаётся отдельной функцией, потому что для CFB это
/// уже не так, а вызывающему всё равно нужно одно и то же имя на оба случая.
pub(crate) fn build_decryptor(
    method: Method,
    master_key: &[u8],
    iv: &[u8],
) -> ShadowsocksrResult<Box<dyn Keystream>> {
    match method {
        Method::Aes128Cfb => Ok(Box::new(
            BufDecryptor::<Aes128>::new_from_slices(master_key, iv).map_err(bad_length)?,
        )),
        Method::Aes192Cfb => Ok(Box::new(
            BufDecryptor::<Aes192>::new_from_slices(master_key, iv).map_err(bad_length)?,
        )),
        Method::Aes256Cfb => Ok(Box::new(
            BufDecryptor::<Aes256>::new_from_slices(master_key, iv).map_err(bad_length)?,
        )),
        // Остальные методы симметричны: та же операция, что при шифровании.
        _ => build_encryptor(method, master_key, iv),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Method; 8] = [
        Method::None,
        Method::Rc4Md5,
        Method::Aes128Cfb,
        Method::Aes192Cfb,
        Method::Aes256Cfb,
        Method::Aes128Ctr,
        Method::Aes192Ctr,
        Method::Aes256Ctr,
    ];

    /// IV на запись — всегда случайные байты (см. документ [`kdf`]); здесь,
    /// в тестах самого шифра, откуда именно взялись байты — неважно, лишь
    /// бы длина совпадала с тем, чего ждёт метод.
    fn fixed_iv(method: Method, filler: u8) -> Vec<u8> {
        vec![filler; method.iv_len()]
    }

    /// Разворачивает результат постройки шифра, называя метод в панике —
    /// `.expect(method.name())` того же не даёт: `clippy::expect_fun_call`
    /// запрещает вызов функции внутри `expect` (сообщение считалось бы даже
    /// при успехе).
    fn built<T>(result: ShadowsocksrResult<T>, method: Method) -> T {
        result.unwrap_or_else(|err| panic!("{}: {err}", method.name()))
    }

    #[test]
    fn every_method_round_trips_encryption() {
        for method in ALL {
            let key = kdf::evp_bytes_to_key("пароль".as_bytes(), method.key_len());
            let iv = fixed_iv(method, 9);
            let mut enc = built(build_encryptor(method, &key, &iv), method);
            let mut dec = built(build_decryptor(method, &key, &iv), method);

            let plaintext = b"shadowsocksr keeps this data secret from onlookers".to_vec();
            let mut wire = plaintext.clone();
            enc.apply(&mut wire);
            if method.encrypts() {
                assert_ne!(wire, plaintext, "{}: шифр не изменил байты", method.name());
            }
            dec.apply(&mut wire);
            assert_eq!(wire, plaintext, "{}", method.name());
        }
    }

    #[test]
    fn a_stream_cipher_keeps_state_across_several_calls() {
        // Соединение читается кусками, а не одним вызовом: если бы шифр
        // сбрасывал состояние между `apply`, второй кусок расшифровался бы в
        // мусор.
        for method in [Method::Aes256Cfb, Method::Aes256Ctr, Method::Rc4Md5] {
            let key = kdf::evp_bytes_to_key("пароль".as_bytes(), method.key_len());
            let iv = fixed_iv(method, 9);
            let mut enc = built(build_encryptor(method, &key, &iv), method);
            let mut dec = built(build_decryptor(method, &key, &iv), method);

            let mut whole = b"one-two-three-four-five".to_vec();
            enc.apply(&mut whole);

            // Тот же шифр, но применённый кусками по три байта.
            let mut enc_piecewise = built(build_encryptor(method, &key, &iv), method);
            let mut piecewise = b"one-two-three-four-five".to_vec();
            for chunk in piecewise.chunks_mut(3) {
                enc_piecewise.apply(chunk);
            }
            assert_eq!(whole, piecewise, "{}", method.name());

            dec.apply(&mut whole);
            assert_eq!(whole, b"one-two-three-four-five", "{}", method.name());
        }
    }

    #[test]
    fn none_does_not_touch_the_bytes() {
        let mut cipher = build_encryptor(Method::None, b"", b"").expect("none всегда строится");
        let mut data = b"as is".to_vec();
        cipher.apply(&mut data);
        assert_eq!(&data, b"as is");
    }
}
