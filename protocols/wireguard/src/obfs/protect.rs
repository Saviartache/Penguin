//! Защита заголовков AmneziaWG 3 (`header_protection_key`): поток ChaCha20
//! (IETF, nonce 12 байт, счётчик с нуля) накладывается на кадр; nonce — первые
//! 12 байт случайного padding `Sx` той же датаграммы (`HeaderProtectionCipher`
//! в `device/noise-protocol.go`). Рукопожатие закрывается целиком, пакет
//! данных — только 16 байт заголовка (`device/send.go`, `device/receive.go`).

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};

/// Длина ключа (`HeaderCipherKeySize`).
pub(crate) const KEY_LEN: usize = 32;

/// Длина nonce и наименьший `Sx` при защите (`HeaderCipherNonceSize`).
pub(crate) const NONCE_LEN: usize = 12;

/// Ключ защиты заголовков.
#[derive(Clone)]
pub(crate) struct HeaderKey([u8; KEY_LEN]);

impl HeaderKey {
    /// Ключ из разобранных байт.
    pub(super) const fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Накладывает поток на `datagram[start..end]`: и закрывает, и снимает.
    /// `false` — датаграмма короче nonce или кадр задевает nonce.
    pub(super) fn apply(&self, datagram: &mut [u8], start: usize, end: usize) -> bool {
        let Some((nonce, rest)) = datagram.split_first_chunk_mut::<NONCE_LEN>() else {
            return false;
        };
        let Some(frame) = start
            .checked_sub(NONCE_LEN)
            .zip(end.checked_sub(NONCE_LEN))
            .and_then(|(from, to)| rest.get_mut(from..to))
        else {
            return false;
        };
        self.cipher(nonce).apply_keystream(frame);
        true
    }

    /// Первые 4 байта потока (`typeHash` эталона): маска поля типа.
    pub(super) fn type_mask(&self, datagram: &[u8]) -> Option<[u8; 4]> {
        let nonce = datagram.first_chunk::<NONCE_LEN>()?;
        let mut mask = [0u8; 4];
        self.cipher(nonce).apply_keystream(&mut mask);
        Some(mask)
    }

    fn cipher(&self, nonce: &[u8; NONCE_LEN]) -> ChaCha20 {
        ChaCha20::new(&self.0.into(), &(*nonce).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ключ 00..1f и nonce RFC 8439 §2.3.2.
    fn sample() -> (HeaderKey, [u8; NONCE_LEN]) {
        let mut key = [0u8; KEY_LEN];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let nonce = [0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        (HeaderKey::new(key), nonce)
    }

    /// Внешний вектор: `openssl enc -chacha20 -K 00..1f -iv 00000000||nonce` над 16 нулями.
    const KEYSTREAM: [u8; 16] = [
        0x8a, 0xdc, 0x91, 0xfd, 0x9f, 0xf4, 0xf0, 0xf5, 0x1b, 0x0f, 0xad, 0x50, 0xff, 0x15, 0xd6,
        0x37,
    ];

    #[test]
    fn the_keystream_matches_openssl_with_the_counter_starting_at_zero() {
        let (key, nonce) = sample();
        let mut datagram = [0u8; NONCE_LEN + 16];
        datagram[..NONCE_LEN].copy_from_slice(&nonce);
        assert!(key.apply(&mut datagram, NONCE_LEN, NONCE_LEN + 16));
        assert_eq!(datagram[NONCE_LEN..], KEYSTREAM);
        assert_eq!(datagram[..NONCE_LEN], nonce, "nonce не тронут");
    }

    #[test]
    fn the_type_mask_is_the_first_four_bytes_of_the_stream() {
        let (key, nonce) = sample();
        let mut datagram = [0u8; 40];
        datagram[..NONCE_LEN].copy_from_slice(&nonce);
        assert_eq!(key.type_mask(&datagram), Some([0x8a, 0xdc, 0x91, 0xfd]));
    }

    #[test]
    fn the_frame_offset_does_not_shift_the_stream() {
        // Поток всегда с нуля, где бы кадр ни начинался (за `Sx` любой длины).
        let (key, nonce) = sample();
        let mut datagram = [0u8; 20 + 16];
        datagram[..NONCE_LEN].copy_from_slice(&nonce);
        assert!(key.apply(&mut datagram, 20, 36));
        assert_eq!(datagram[20..], KEYSTREAM);
    }

    #[test]
    fn applying_twice_restores_the_frame() {
        let (key, nonce) = sample();
        let mut datagram = [0x5Au8; 64];
        datagram[..NONCE_LEN].copy_from_slice(&nonce);
        let original = datagram;
        assert!(key.apply(&mut datagram, 16, 64));
        assert_ne!(datagram, original);
        assert!(key.apply(&mut datagram, 16, 64));
        assert_eq!(datagram, original);
    }

    #[test]
    fn a_frame_overlapping_the_nonce_or_a_short_datagram_is_refused() {
        let (key, _) = sample();
        assert!(!key.apply(&mut [0u8; 8], 0, 4));
        assert!(!key.apply(&mut [0u8; 40], 4, 20));
        assert!(!key.apply(&mut [0u8; 40], 12, 41));
        assert_eq!(key.type_mask(&[0u8; 11]), None);
    }
}
