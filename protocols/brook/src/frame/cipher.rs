//! Шифр одного направления: ключ фиксирован, нонс расписан по своим правилам.
//!
//! Каждый вызов [`Cipher::seal`] и [`Cipher::open`] использует текущее
//! значение нонса и сразу двигает его дальше ([`nonce::increment`]). Это не
//! придумано здесь: так же, по одному шагу на операцию, устроены `Write` и
//! `Read` у эталона (`streamclient.go`) — за один кадр TCP нонс двигается
//! дважды, один раз под длину и один раз под данные, и оба раза получают
//! разные значения.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce as RingNonce, UnboundKey};

use crate::error::{BrookError, BrookResult};
use crate::frame::key;
use crate::frame::nonce::{self, Nonce};

/// Длина метки подлинности AES-GCM.
pub const TAG_LEN: usize = 16;

/// Шифр направления: ключ и нонс, который меняется на каждой операции.
pub struct Cipher {
    key: LessSafeKey,
    nonce: Nonce,
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Ни ключа, ни нонса: первый — секрет, второй по нему считается.
        f.debug_struct("Cipher").finish()
    }
}

impl Cipher {
    /// Собирает шифр: ключ выводится из пароля и стартового нонса, он же
    /// становится первым значением счётчика.
    pub fn new(password: &[u8], nonce: Nonce) -> BrookResult<Self> {
        let bytes = key::derive(password, &nonce)?;
        let unbound = UnboundKey::new(&AES_256_GCM, &bytes)
            .map_err(|_| BrookError::crypto("ключ не подошёл шифру"))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            nonce,
        })
    }

    /// Зашифровывает кусок, дописывает метку и двигает нонс.
    pub fn seal(&mut self, plain: &[u8]) -> BrookResult<Vec<u8>> {
        let mut buffer = plain.to_vec();
        let current = RingNonce::assume_unique_for_key(self.nonce);
        self.key
            .seal_in_place_append_tag(current, Aad::empty(), &mut buffer)
            .map_err(|_| BrookError::crypto("не зашифровалось"))?;
        nonce::increment(&mut self.nonce);
        Ok(buffer)
    }

    /// Расшифровывает на месте, возвращает длину открытого текста и двигает
    /// нонс.
    ///
    /// `Err` — метка не сошлась. Для AEAD это не шум на линии: она заверяет
    /// данные, и не сошедшаяся означает или неверный пароль, или правку по
    /// дороге, или разошедшиеся часы (см. документ [`crate`]). Продолжать
    /// после неё нельзя ни в одном из случаев.
    pub fn open(&mut self, buffer: &mut [u8]) -> BrookResult<usize> {
        let current = RingNonce::assume_unique_for_key(self.nonce);
        let plain = self
            .key
            .open_in_place(current, Aad::empty(), buffer)
            .map_err(|_| BrookError::Rejected)?;
        let len = plain.len();
        nonce::increment(&mut self.nonce);
        Ok(len)
    }
}

/// Сколько байт займёт кусок в зашифрованном виде.
pub fn sealed_len(plain: usize) -> usize {
    plain + TAG_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(nonce: Nonce) -> (Cipher, Cipher) {
        (
            Cipher::new(b"secret", nonce).expect("собирается"),
            Cipher::new(b"secret", nonce).expect("собирается"),
        )
    }

    #[test]
    fn what_is_sealed_can_be_opened() {
        let (mut send, mut recv) = pair([1u8; 12]);
        let mut wire = send.seal(b"payload").expect("шифруется");
        assert_eq!(wire.len(), sealed_len(b"payload".len()));

        let len = recv.open(&mut wire).expect("расшифровывается");
        assert_eq!(&wire[..len], b"payload");
    }

    #[test]
    fn the_second_piece_uses_a_different_nonce_than_the_first() {
        // У эталона за один кадр нонс двигается дважды: под длину и под
        // данные. Повторить пару «ключ, нонс» для AEAD значит раскрыть оба
        // сообщения, поэтому два подряд вызова обязаны шифровать по-разному.
        let (mut send, _recv) = pair([9u8; 12]);
        let first = send.seal(b"one").expect("шифруется");
        let second = send.seal(b"one").expect("шифруется");
        assert_ne!(first, second, "тот же нонс использован дважды");
    }

    #[test]
    fn sender_and_receiver_stay_in_lockstep() {
        // Это и есть замена общему `ChunkStream`: там нонс каждой стороны
        // начинается с нуля, здесь — со случайной соли, но шаг тот же самый.
        let (mut send, mut recv) = pair([3u8; 12]);
        let mut a = send.seal(b"first").expect("шифруется");
        let mut b = send.seal(b"second").expect("шифруется");

        assert_eq!(recv.open(&mut a).expect("первый"), b"first".len());
        assert_eq!(recv.open(&mut b).expect("второй"), b"second".len());
    }

    #[test]
    fn a_changed_byte_is_noticed() {
        let (mut send, mut recv) = pair([5u8; 12]);
        let mut wire = send.seal(b"payload").expect("шифруется");
        wire[0] ^= 0x01;
        assert!(matches!(recv.open(&mut wire), Err(BrookError::Rejected)));
    }

    #[test]
    fn a_wrong_password_looks_exactly_like_a_tampered_byte() {
        // Оба случая дают одну и ту же ошибку: AEAD не умеет их различить, и
        // притворяться, что умеет, нельзя.
        let mut send = Cipher::new(b"secret", [2u8; 12]).expect("собирается");
        let mut recv = Cipher::new("другой пароль".as_bytes(), [2u8; 12]).expect("собирается");

        let mut wire = send.seal(b"payload").expect("шифруется");
        assert!(matches!(recv.open(&mut wire), Err(BrookError::Rejected)));
    }
}
