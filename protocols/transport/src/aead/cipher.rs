//! Шифрование куска: ключ, счётчик, метка подлинности.
//!
//! Нонс — счётчик little-endian (от младшего байта), отдельный на каждое
//! направление. Пара «ключ, нонс» не повторяется: ключ сеансовый, счётчик с нуля.

use bytes::BytesMut;
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
        self.seal_in_place(&mut buffer, 0)?;
        Ok(buffer)
    }

    /// Шифрует `buf[from..]` на месте и дописывает метку; без аллокаций.
    pub fn seal_in_place(&mut self, buf: &mut Vec<u8>, from: usize) -> TransportResult<()> {
        let tag = self.seal_slice(&mut buf[from..])?;
        buf.extend_from_slice(tag.as_ref());
        Ok(())
    }

    /// Как [`Self::seal`], но дописывает в `out` без промежуточных буферов.
    pub fn seal_into(&mut self, plain: &[u8], out: &mut BytesMut) -> TransportResult<()> {
        let start = out.len();
        out.extend_from_slice(plain);
        let tag = self.seal_slice(&mut out[start..])?;
        out.extend_from_slice(tag.as_ref());
        Ok(())
    }

    fn seal_slice(&mut self, data: &mut [u8]) -> TransportResult<ring::aead::Tag> {
        let nonce = self.take_nonce();
        self.key
            .seal_in_place_separate_tag(nonce, Aad::empty(), data)
            .map_err(|_| TransportError::malformed("не зашифровалось"))
    }

    /// Расшифровывает на месте, возвращает длину открытого текста.
    /// `Err` — метка не сошлась (чужой пароль или правка по дороге): продолжать нельзя.
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

/// Прибавляет единицу к числу little-endian.
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
        let mut send = cipher(Algorithm::Aes128Gcm);
        let mut first = send.seal(b"one").expect("шифруется");
        let mut second = send.seal(b"two").expect("шифруется");

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
        let mut nonce = [0u8; NONCE_LEN];
        increment(&mut nonce);
        assert_eq!(nonce[0], 1, "единица легла не в младший байт");

        let mut nonce = [0xff, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        increment(&mut nonce);
        assert_eq!(nonce[..2], [0x00, 0x01], "перенос ушёл не туда");
    }

    #[test]
    fn the_counter_wraps_without_panicking() {
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
