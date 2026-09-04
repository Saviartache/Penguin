//! Шифрование куска: ключ, счётчик, метка подлинности.
//!
//! # Счётчик, а не случайность
//!
//! Нонс здесь не бросается, а считается: двенадцать байт, число **от младшего
//! байта к старшему**, плюс единица после каждой операции. Порядок байт — не
//! мелочь и не вкус: при обратном порядке первые 65535 кусков совпадут с
//! правильными, а дальше разойдутся. Выглядит это как соединение, которое
//! работает час и потом рвётся, и ищется оно днями.
//!
//! Отправка и приём считают **раздельно**: это два независимых потока байт,
//! и общий счётчик рассинхронизировал бы их на первом же ответе сервера.
//!
//! # Почему нельзя повторить пару «ключ, счётчик»
//!
//! Для AEAD это не «слабее», а «раскрыто»: два разных сообщения под одной
//! парой выдают оба открытых текста и позволяют подделать метку. Поэтому
//! ключ здесь всегда сеансовый — выведенный из случайной соли, — и счётчик
//! начинается с нуля ровно один раз на соединение.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};

use crate::crypto::method::{Method, TAG_LEN};
use crate::error::{ShadowsocksError, ShadowsocksResult};

/// Длина нонса у всех трёх методов.
pub const NONCE_LEN: usize = 12;

/// Шифр одного направления: ключ и его счётчик.
pub struct Cipher {
    key: LessSafeKey,
    nonce: [u8; NONCE_LEN],
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Ни ключа, ни счётчика: первый — секрет, второй по нему считается.
        f.debug_struct("Cipher").finish()
    }
}

impl Cipher {
    /// Собирает шифр вокруг сеансового ключа.
    pub fn new(method: Method, key: &[u8]) -> ShadowsocksResult<Self> {
        let key = UnboundKey::new(method.algorithm(), key)
            .map_err(|_| ShadowsocksError::crypto("ключ не той длины"))?;
        Ok(Self {
            key: LessSafeKey::new(key),
            nonce: [0u8; NONCE_LEN],
        })
    }

    /// Зашифровывает кусок и дописывает метку подлинности.
    pub fn seal(&mut self, plain: &[u8]) -> ShadowsocksResult<Vec<u8>> {
        let mut buffer = plain.to_vec();
        let nonce = self.take_nonce();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut buffer)
            .map_err(|_| ShadowsocksError::crypto("не зашифровалось"))?;
        Ok(buffer)
    }

    /// Расшифровывает кусок на месте и возвращает длину открытого текста.
    ///
    /// `Err` — метка не сошлась. Это не «шум на линии»: AEAD заверяет данные,
    /// и не сошедшаяся метка означает либо неверный пароль, либо правку по
    /// дороге. Продолжать после неё нельзя ни в каком случае.
    pub fn open(&mut self, buffer: &mut [u8]) -> ShadowsocksResult<usize> {
        let nonce = self.take_nonce();
        let plain = self
            .key
            .open_in_place(nonce, Aad::empty(), buffer)
            .map_err(|_| ShadowsocksError::Rejected)?;
        Ok(plain.len())
    }

    /// Текущий нонс; счётчик при этом сдвигается.
    fn take_nonce(&mut self) -> Nonce {
        let current = Nonce::assume_unique_for_key(self.nonce);
        increment(&mut self.nonce);
        current
    }
}

/// Прибавляет единицу к числу, записанному от младшего байта к старшему.
///
/// Свободная функция с тестом, потому что ошибка здесь не видна ни на сборке,
/// ни на первом мегабайте.
fn increment(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut() {
        let (value, carry) = byte.overflowing_add(1);
        *byte = value;
        if !carry {
            return;
        }
    }
}

/// Сколько байт займёт кусок в зашифрованном виде.
pub fn sealed_len(plain: usize) -> usize {
    plain + TAG_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher(method: Method) -> Cipher {
        Cipher::new(method, &vec![7u8; method.key_len()]).expect("ключ подходит")
    }

    #[test]
    fn what_is_sealed_can_be_opened() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            let mut send = cipher(method);
            let mut recv = cipher(method);

            let mut wire = send.seal(b"payload").expect("шифруется");
            assert_eq!(wire.len(), sealed_len(b"payload".len()));

            let len = recv.open(&mut wire).expect("расшифровывается");
            assert_eq!(&wire[..len], b"payload", "{}", method.name());
        }
    }

    #[test]
    fn the_counter_moves_after_every_piece() {
        // Два одинаковых куска обязаны дать разные байты: иначе счётчик стоит
        // на месте, и пара «ключ, счётчик» повторяется.
        let mut send = cipher(Method::Aes256Gcm);
        let first = send.seal(b"same").expect("шифруется");
        let second = send.seal(b"same").expect("шифруется");
        assert_ne!(first, second);
    }

    #[test]
    fn the_pieces_are_read_in_the_order_they_were_written() {
        let mut send = cipher(Method::Aes256Gcm);
        let mut recv = cipher(Method::Aes256Gcm);

        let mut first = send.seal(b"one").expect("шифруется");
        let mut second = send.seal(b"two").expect("шифруется");

        let len = recv.open(&mut first).expect("расшифровывается");
        assert_eq!(&first[..len], b"one");
        let len = recv.open(&mut second).expect("расшифровывается");
        assert_eq!(&second[..len], b"two");
    }

    #[test]
    fn a_piece_read_out_of_order_is_refused() {
        // Счётчик у приёма свой, и пропущенный кусок означает не «потерю», а
        // разъехавшийся поток: дальше всё будет мусором.
        let mut send = cipher(Method::Aes256Gcm);
        let mut recv = cipher(Method::Aes256Gcm);

        let _skipped = send.seal(b"one").expect("шифруется");
        let mut second = send.seal(b"two").expect("шифруется");

        assert!(recv.open(&mut second).is_err());
    }

    #[test]
    fn a_changed_byte_is_noticed() {
        // В этом весь смысл AEAD: правку по дороге видно. У потоковых шифров
        // прежних версий её не видно вовсе.
        let mut send = cipher(Method::Aes256Gcm);
        let mut recv = cipher(Method::Aes256Gcm);

        let mut wire = send.seal(b"payload").expect("шифруется");
        wire[0] ^= 1;
        assert!(recv.open(&mut wire).is_err());
    }

    #[test]
    fn a_wrong_key_is_told_apart_from_a_broken_link() {
        // Не сошедшаяся метка на первом же куске — это почти всегда неверный
        // пароль, и повторять попытку с ним бессмысленно.
        let mut send = cipher(Method::Aes256Gcm);
        let mut recv = Cipher::new(Method::Aes256Gcm, &[9u8; 32]).expect("ключ подходит");

        let mut wire = send.seal(b"payload").expect("шифруется");
        assert!(matches!(
            recv.open(&mut wire),
            Err(ShadowsocksError::Rejected)
        ));
    }

    #[test]
    fn the_counter_counts_from_the_low_byte() {
        // Обратный порядок дал бы совпадение на первых 65535 кусках и разрыв
        // дальше: соединение, которое работает час и потом рвётся.
        let mut nonce = [0u8; NONCE_LEN];
        increment(&mut nonce);
        assert_eq!(nonce[0], 1, "единица легла не в младший байт");
        assert_eq!(nonce[1..], [0u8; NONCE_LEN - 1]);
    }

    #[test]
    fn the_counter_carries_over() {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[0] = 0xFF;
        increment(&mut nonce);
        assert_eq!(nonce[0], 0);
        assert_eq!(nonce[1], 1);

        // И через несколько байт тоже.
        let mut nonce = [0xFFu8; NONCE_LEN];
        nonce[NONCE_LEN - 1] = 0;
        increment(&mut nonce);
        assert_eq!(nonce[..NONCE_LEN - 1], [0u8; NONCE_LEN - 1]);
        assert_eq!(nonce[NONCE_LEN - 1], 1);
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        assert!(Cipher::new(Method::Aes256Gcm, &[0u8; 16]).is_err());
    }
}
