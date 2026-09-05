//! Шифр одного направления: XChaCha20-Poly1305 с нонсом, который не
//! повторяется на проводе, кроме самого первого раза.
//!
//! # Режим «неявного нонса»
//!
//! Для TCP нонс уходит на проводе только в первой операции этого
//! направления; дальше обе стороны знают его сами — держат в памяти и
//! прибавляют единицу перед каждой следующей операцией (`nonce`). Раздельные
//! типы для отправки и приёма — не дублирование: у отправителя нонс рождается
//! случайным, у приёмника — приходит с провода, и общий тип одной строкой
//! спрятал бы, какая сторона что делает.
//!
//! Ключ у обоих направлений один и тот же (см. `keying`); отдельные нонсы —
//! то, что не даёт паре «ключ, нонс» повториться между направлениями.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use crate::error::{MieruError, MieruResult};
use crate::keying::Key;
use crate::nonce::{self, Nonce};

/// Длина метки подлинности.
pub const TAG_LEN: usize = 16;

fn aead(key: &Key) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

/// Шифр направления «от нас».
pub struct SendCipher {
    aead: XChaCha20Poly1305,
    username: String,
    nonce: Option<Nonce>,
}

impl SendCipher {
    /// Собирает шифр. Нонс ещё не выбран — он родится при первой операции.
    pub fn new(key: &Key, username: &str) -> Self {
        Self {
            aead: aead(key),
            username: username.to_owned(),
            nonce: None,
        }
    }

    /// Шифрует кусок и дописывает результат в `out`.
    ///
    /// Если это первая операция на этом направлении, перед шифротекстом в
    /// `out` уходит и сам нонс (24 байта) — больше он не повторится ни разу.
    pub fn seal(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> MieruResult<()> {
        let nonce = match self.nonce {
            None => {
                let mut fresh = nonce::random();
                nonce::apply_hint(&mut fresh, &self.username);
                out.extend_from_slice(&fresh);
                self.nonce = Some(fresh);
                fresh
            }
            Some(mut current) => {
                nonce::increment(&mut current);
                self.nonce = Some(current);
                current
            }
        };

        let sealed = self
            .aead
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|_| MieruError::malformed("кусок не зашифровался"))?;
        out.extend_from_slice(&sealed);
        Ok(())
    }
}

/// Шифр направления «к нам».
pub struct RecvCipher {
    aead: XChaCha20Poly1305,
    nonce: Option<Nonce>,
}

impl RecvCipher {
    /// Собирает шифр.
    pub fn new(key: &Key) -> Self {
        Self {
            aead: aead(key),
            nonce: None,
        }
    }

    /// Ждёт ли этот шифр нонс на проводе следующей операцией.
    ///
    /// Нужен тому, кто читает сокет: сколько байт снять с провода до
    /// шифротекста, известно только по этому флагу.
    pub fn expects_wire_nonce(&self) -> bool {
        self.nonce.is_none()
    }

    /// Расшифровывает кусок.
    ///
    /// `wire_nonce` — байты нонса с провода; обязателен ровно тогда, когда
    /// [`Self::expects_wire_nonce`] вернула `true`, и не принимается иначе:
    /// нонс на проводе появляется только один раз за направление.
    pub fn open(&mut self, wire_nonce: Option<&[u8]>, ciphertext: &[u8]) -> MieruResult<Vec<u8>> {
        let nonce = match (self.nonce, wire_nonce) {
            (None, Some(bytes)) => {
                let array: Nonce = bytes
                    .try_into()
                    .map_err(|_| MieruError::malformed("нонс не той длины"))?;
                self.nonce = Some(array);
                array
            }
            (Some(mut current), None) => {
                nonce::increment(&mut current);
                self.nonce = Some(current);
                current
            }
            (None, None) => {
                return Err(MieruError::malformed("ждали нонс с провода, не получили"));
            }
            (Some(_), Some(_)) => {
                return Err(MieruError::malformed(
                    "нонс с провода пришёл повторно на этом направлении",
                ));
            }
        };

        self.aead
            .decrypt(XNonce::from_slice(&nonce), ciphertext)
            .map_err(|_| MieruError::Rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        [7u8; 32]
    }

    #[test]
    fn what_is_sealed_can_be_opened() {
        let mut send = SendCipher::new(&key(), "alice");
        let mut recv = RecvCipher::new(&key());

        let mut wire = Vec::new();
        send.seal(b"hello", &mut wire).expect("шифруется");

        // Первая операция несёт нонс: 24 байта плюс кусок плюс метка.
        assert_eq!(wire.len(), 24 + 5 + TAG_LEN);

        let (nonce, ciphertext) = wire.split_at(24);
        let opened = recv
            .open(Some(nonce), ciphertext)
            .expect("расшифровывается");
        assert_eq!(opened, b"hello");
    }

    #[test]
    fn the_second_operation_carries_no_nonce_on_the_wire() {
        let mut send = SendCipher::new(&key(), "alice");
        let mut first = Vec::new();
        send.seal(b"one", &mut first).expect("шифруется");

        let mut second = Vec::new();
        send.seal(b"two", &mut second).expect("шифруется");
        assert_eq!(
            second.len(),
            3 + TAG_LEN,
            "второй раз нонс не должен уезжать"
        );
    }

    #[test]
    fn the_receiver_must_advance_through_every_piece_in_order() {
        let mut send = SendCipher::new(&key(), "alice");
        let mut recv = RecvCipher::new(&key());

        let mut first = Vec::new();
        send.seal(b"one", &mut first).expect("шифруется");
        let mut second = Vec::new();
        send.seal(b"two", &mut second).expect("шифруется");

        let (nonce, ciphertext) = first.split_at(24);
        recv.open(Some(nonce), ciphertext).expect("первый кусок");

        // Второй кусок зашифрован под следующим шагом счётчика: пропустить
        // первый и открыть сразу второй нельзя, счётчик приёмника не сойдётся.
        assert!(recv.open(None, &second).is_ok(), "второй кусок по порядку");
    }

    #[test]
    fn a_changed_byte_is_rejected_not_silently_accepted() {
        let mut send = SendCipher::new(&key(), "alice");
        let mut recv = RecvCipher::new(&key());

        let mut wire = Vec::new();
        send.seal(b"hello", &mut wire).expect("шифруется");
        let last = wire.len() - 1;
        wire[last] ^= 0x01;

        let (nonce, ciphertext) = wire.split_at(24);
        assert!(matches!(
            recv.open(Some(nonce), ciphertext),
            Err(MieruError::Rejected)
        ));
    }

    #[test]
    fn the_wrong_key_cannot_open_it() {
        let mut send = SendCipher::new(&key(), "alice");
        let mut recv = RecvCipher::new(&[9u8; 32]);

        let mut wire = Vec::new();
        send.seal(b"hello", &mut wire).expect("шифруется");
        let (nonce, ciphertext) = wire.split_at(24);
        assert!(recv.open(Some(nonce), ciphertext).is_err());
    }
}
