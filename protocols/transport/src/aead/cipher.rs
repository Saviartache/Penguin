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

use crate::aead::algorithm::{Algorithm, NONCE_LEN, TAG_LEN};
use crate::error::{TransportError, TransportResult};

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
    pub fn new(algorithm: Algorithm, key: &[u8]) -> TransportResult<Self> {
        let key = UnboundKey::new(algorithm.ring(), key)
            .map_err(|_| TransportError::config("ключ не той длины"))?;
        Ok(Self {
            key: LessSafeKey::new(key),
            nonce: [0u8; NONCE_LEN],
        })
    }

    /// Зашифровывает кусок и дописывает метку подлинности.
    pub fn seal(&mut self, plain: &[u8]) -> TransportResult<Vec<u8>> {
        let mut buffer = plain.to_vec();
        let nonce = self.take_nonce();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut buffer)
            .map_err(|_| TransportError::malformed("не зашифровалось"))?;
        Ok(buffer)
    }

    /// Расшифровывает кусок на месте и возвращает длину открытого текста.
    ///
    /// `Err` — метка не сошлась. Это не «шум на линии»: AEAD заверяет данные,
    /// и не сошедшаяся метка означает либо неверный пароль, либо правку по
    /// дороге. Продолжать после неё нельзя ни в каком случае.
    pub fn open(&mut self, buffer: &mut [u8]) -> TransportResult<usize> {
        let nonce = self.take_nonce();
        let plain = self
            .key
            .open_in_place(nonce, Aad::empty(), buffer)
            .map_err(|_| TransportError::Rejected)?;
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

    const ALL: [Algorithm; 3] = [
        Algorithm::Aes128Gcm,
        Algorithm::Aes256Gcm,
        Algorithm::ChaCha20Poly1305,
    ];

    fn cipher(algorithm: Algorithm) -> Cipher {
        Cipher::new(algorithm, &vec![7u8; algorithm.key_len()]).expect("ключ подходит")
    }

    #[test]
    fn what_is_sealed_can_be_opened() {
        for algorithm in ALL {
            let mut send = cipher(algorithm);
            let mut recv = cipher(algorithm);

            let mut wire = send.seal(b"payload").expect("шифруется");
            assert_eq!(wire.len(), sealed_len(b"payload".len()));

            let len = recv.open(&mut wire).expect("расшифровывается");
            assert_eq!(&wire[..len], b"payload", "{}", algorithm.name());
        }
    }

    #[test]
    fn the_counter_moves_and_the_order_of_the_pieces_matters() {
        // Второй кусок под тем же ключом шифруется другим нонсом; поменять
        // куски местами при расшифровке нельзя.
        let mut send = cipher(Algorithm::Aes128Gcm);
        let mut first = send.seal(b"one").expect("шифруется");
        let mut second = send.seal(b"two").expect("шифруется");

        // Второму куску достался следующий шаг счётчика: первым его не
        // открыть, сколько бы правильным ни был ключ.
        let mut ahead = cipher(Algorithm::Aes128Gcm);
        assert!(ahead.open(&mut second.clone()).is_err(), "порядок не важен");

        let mut recv = cipher(Algorithm::Aes128Gcm);
        recv.open(&mut first).expect("первый");
        recv.open(&mut second).expect("второй");
    }

    #[test]
    fn a_changed_byte_is_noticed() {
        let mut send = cipher(Algorithm::Aes256Gcm);
        let mut recv = cipher(Algorithm::Aes256Gcm);

        let mut wire = send.seal(b"payload").expect("шифруется");
        wire[0] ^= 0x01;
        assert!(matches!(
            recv.open(&mut wire),
            Err(TransportError::Rejected)
        ));
    }

    #[test]
    fn the_counter_counts_from_the_low_byte_up() {
        // При обратном порядке первые 65535 кусков совпали бы с правильными,
        // а дальше разошлись бы: соединение работает час и рвётся.
        let mut nonce = [0u8; NONCE_LEN];
        increment(&mut nonce);
        assert_eq!(nonce[0], 1, "единица легла не в младший байт");

        let mut nonce = [0xff, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        increment(&mut nonce);
        assert_eq!(nonce[..2], [0x00, 0x01], "перенос ушёл не туда");
    }

    #[test]
    fn the_counter_wraps_without_panicking() {
        // Столько кусков в одном соединении не бывает, но паника здесь
        // оборвала бы тоннель, а не соединение.
        let mut nonce = [0xff; NONCE_LEN];
        increment(&mut nonce);
        assert_eq!(nonce, [0u8; NONCE_LEN]);
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        assert!(Cipher::new(Algorithm::Aes128Gcm, &[0u8; 15]).is_err());
        assert!(Cipher::new(Algorithm::Aes256Gcm, &[0u8; 16]).is_err());
    }
}
