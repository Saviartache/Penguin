//! Примитивы Noise: `HASH`, `HMAC`, KDF, `MAC`, `AEAD`
//! (`wireguard.com/protocol/`; формулы - `device/noise-helpers.go`, `device/cookie.go`).
//!
//! `HMAC()` - обычный HMAC (RFC 2104) над BLAKE2s-256, `MAC()` (`mac1`/`mac2`) -
//! керированный BLAKE2s. Крейт `hmac` не подходит: у BLAKE2 «ленивая» буферизация
//! блока, `Hmac<Blake2s256>` не собирается, поэтому HMAC собран вручную.

use blake2::Blake2s256;
use blake2::digest::Digest;
use blake2::digest::consts::U16;
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as AeadKeyInit, Nonce};

use crate::crypto::constants::{AEAD_TAG_LEN, KEY_LEN, MAC_LEN};
use crate::error::{WireguardError, WireguardResult};

const BLAKE2S_BLOCK_LEN: usize = 64;

/// `HASH(data) = BLAKE2s-256(data)`.
pub fn hash(parts: &[&[u8]]) -> [u8; KEY_LEN] {
    let mut hasher = Blake2s256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// `HMAC(key, input)` - HMAC-BLAKE2s-256 по RFC 2104.
fn hmac_blake2s(key: &[u8], parts: &[&[u8]]) -> [u8; KEY_LEN] {
    let mut key_block = [0u8; BLAKE2S_BLOCK_LEN];
    if key.len() > BLAKE2S_BLOCK_LEN {
        key_block[..KEY_LEN].copy_from_slice(&hash(&[key]));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLAKE2S_BLOCK_LEN];
    let mut opad = [0x5cu8; BLAKE2S_BLOCK_LEN];
    for i in 0..BLAKE2S_BLOCK_LEN {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Blake2s256::new();
    inner.update(ipad);
    for part in parts {
        inner.update(part);
    }
    let inner_digest = inner.finalize();

    let mut outer = Blake2s256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

/// `Kdf1`: один выход.
pub fn kdf1(chaining_key: &[u8; KEY_LEN], input: &[u8]) -> [u8; KEY_LEN] {
    let temp = hmac_blake2s(chaining_key, &[input]);
    hmac_blake2s(&temp, &[&[0x1]])
}

/// `Kdf2`: новый `chaining_key` и ключ AEAD (`KDF2` в `device/noise-helpers.go`).
pub fn kdf2(chaining_key: &[u8; KEY_LEN], input: &[u8]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let temp = hmac_blake2s(chaining_key, &[input]);
    let ck = hmac_blake2s(&temp, &[&[0x1]]);
    let key = hmac_blake2s(&temp, &[&ck, &[0x2]]);
    (ck, key)
}

/// `Kdf3`: три выхода, для предварительного ключа во втором сообщении.
pub fn kdf3(
    chaining_key: &[u8; KEY_LEN],
    input: &[u8],
) -> ([u8; KEY_LEN], [u8; KEY_LEN], [u8; KEY_LEN]) {
    let temp = hmac_blake2s(chaining_key, &[input]);
    let ck = hmac_blake2s(&temp, &[&[0x1]]);
    let tau = hmac_blake2s(&temp, &[&ck, &[0x2]]);
    let key = hmac_blake2s(&temp, &[&tau, &[0x3]]);
    (ck, tau, key)
}

/// `MAC(key, data)` для `mac1`/`mac2`: керированный BLAKE2s на 16 байт (не HMAC).
pub fn mac(key: &[u8], data: &[u8]) -> [u8; MAC_LEN] {
    type Blake2sMac128 = blake2::Blake2sMac<U16>;

    // Ключ не длиннее 32 байт - предела BLAKE2s.
    #[allow(clippy::expect_used)]
    let mut hasher = <Blake2sMac128 as blake2::digest::KeyInit>::new_from_slice(key)
        .expect("ключ MAC не длиннее предела BLAKE2s");
    blake2::digest::Update::update(&mut hasher, data);
    blake2::digest::Mac::finalize(hasher).into_bytes().into()
}

/// `AEAD(key, counter, plaintext, auth_text)`: ChaCha20-Poly1305, нонс - четыре
/// нулевых байта и счётчик u64 little endian.
pub fn aead_seal(key: &[u8; KEY_LEN], counter: u64, plaintext: &[u8], auth_text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(sealed_len(plaintext.len()));
    out.extend_from_slice(plaintext);
    // Длины рукопожатия малы: шифрование не отказывает.
    #[allow(clippy::expect_used)]
    let tag = aead_seal_in_place(key, counter, &mut out, auth_text)
        .expect("шифрование короткого сообщения не отказывает");
    out.extend_from_slice(&tag);
    out
}

/// Шифрует `buf` на месте и возвращает метку.
pub fn aead_seal_in_place(
    key: &[u8; KEY_LEN],
    counter: u64,
    buf: &mut [u8],
    auth_text: &[u8],
) -> WireguardResult<[u8; AEAD_TAG_LEN]> {
    let tag = ChaCha20Poly1305::new(key.into())
        .encrypt_inout_detached(&nonce_from_counter(counter), auth_text, buf.into())
        .map_err(|_| WireguardError::malformed("сообщение слишком длинное для AEAD"))?;
    Ok(tag.into())
}

/// Обратное к [`aead_seal`]; ошибка - чужой ключ или испорченный пакет.
pub fn aead_open(
    key: &[u8; KEY_LEN],
    counter: u64,
    ciphertext: &[u8],
    auth_text: &[u8],
) -> WireguardResult<Vec<u8>> {
    let mut buf = ciphertext.to_vec();
    let len = aead_open_in_place(key, counter, &mut buf, auth_text)?.len();
    buf.truncate(len);
    Ok(buf)
}

/// Расшифровывает `sealed` (шифротекст и метка) на месте; возвращает открытый текст.
pub fn aead_open_in_place<'a>(
    key: &[u8; KEY_LEN],
    counter: u64,
    sealed: &'a mut [u8],
    auth_text: &[u8],
) -> WireguardResult<&'a mut [u8]> {
    let auth_failed = || WireguardError::Malformed("метка подлинности не сошлась".into());
    let split = sealed
        .len()
        .checked_sub(AEAD_TAG_LEN)
        .ok_or_else(auth_failed)?;
    let (data, tag) = sealed.split_at_mut(split);
    let tag = (&*tag).try_into().map_err(|_| auth_failed())?;
    ChaCha20Poly1305::new(key.into())
        .decrypt_inout_detached(&nonce_from_counter(counter), auth_text, data.into(), &tag)
        .map_err(|_| auth_failed())?;
    Ok(data)
}

/// Длина шифротекста AEAD: открытый текст плюс метка.
pub const fn sealed_len(plaintext_len: usize) -> usize {
    plaintext_len + AEAD_TAG_LEN
}

fn nonce_from_counter(counter: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    bytes.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::constants::{CONSTRUCTION, IDENTIFIER};

    /// BLAKE2s-256 пустой строки: RFC 7693, приложение E; сверено с OpenSSL.
    #[test]
    fn blake2s_matches_the_rfc_7693_test_vector() {
        let digest = hash(&[b""]);
        assert_eq!(
            digest,
            hex32("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
        );
    }

    /// `InitialChainKey` и `InitialHash` сверены с `boringtun` и с OpenSSL.
    #[test]
    fn the_initial_chaining_key_and_hash_match_an_independent_implementation() {
        let initial_chain_key = hash(&[CONSTRUCTION]);
        assert_eq!(
            initial_chain_key,
            [
                96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235,
                66, 6, 248, 114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
            ]
        );

        let initial_hash = hash(&[&initial_chain_key, IDENTIFIER]);
        assert_eq!(
            initial_hash,
            [
                34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108,
                102, 34, 147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
            ]
        );
    }

    #[test]
    fn aead_round_trips() {
        let key = [7u8; KEY_LEN];
        let sealed = aead_seal(&key, 5, b"hello", b"aad");
        assert_eq!(sealed.len(), sealed_len(5));
        let opened = aead_open(&key, 5, &sealed, b"aad").expect("расшифровывается");
        assert_eq!(opened, b"hello");
    }

    #[test]
    fn aead_in_place_matches_the_allocating_form() {
        let key = [7u8; KEY_LEN];
        let mut buf = b"hello".to_vec();
        let tag = aead_seal_in_place(&key, 5, &mut buf, b"aad").expect("шифруется");
        buf.extend_from_slice(&tag);
        assert_eq!(buf, aead_seal(&key, 5, b"hello", b"aad"));
        let opened = aead_open_in_place(&key, 5, &mut buf, b"aad").expect("расшифровывается");
        assert_eq!(opened, b"hello");
    }

    #[test]
    fn aead_rejects_the_wrong_counter() {
        let key = [7u8; KEY_LEN];
        let sealed = aead_seal(&key, 5, b"hello", b"aad");
        assert!(aead_open(&key, 6, &sealed, b"aad").is_err());
    }

    #[test]
    fn aead_rejects_tampered_auth_text() {
        let key = [7u8; KEY_LEN];
        let sealed = aead_seal(&key, 0, b"hello", b"aad-1");
        assert!(aead_open(&key, 0, &sealed, b"aad-2").is_err());
    }

    #[test]
    fn aead_rejects_input_shorter_than_the_tag() {
        assert!(aead_open(&[7u8; KEY_LEN], 0, &[0u8; 3], &[]).is_err());
    }

    #[test]
    fn kdf2_outputs_differ_from_each_other() {
        let ck = [1u8; KEY_LEN];
        let (a, b) = kdf2(&ck, b"input");
        assert_ne!(a, b);
    }

    #[test]
    fn kdf3_first_two_outputs_match_kdf2() {
        let ck = [1u8; KEY_LEN];
        let (ck2, key2) = kdf2(&ck, b"input");
        let (ck3, tau3, _key3) = kdf3(&ck, b"input");
        assert_eq!(ck2, ck3);
        assert_eq!(key2, tau3);
    }

    #[test]
    fn kdf1_matches_the_first_two_rounds_of_kdf2() {
        let ck = [1u8; KEY_LEN];
        let (ck2, _key2) = kdf2(&ck, b"input");
        assert_eq!(kdf1(&ck, b"input"), ck2);
    }

    #[test]
    fn mac_depends_on_the_key_not_only_the_data() {
        let data = b"mac1 covers everything before it";
        let mac_a = mac(&[1u8; 32], data);
        let mac_b = mac(&[2u8; 32], data);
        assert_ne!(mac_a, mac_b);
    }

    fn hex32(text: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("тест содержит hex");
        }
        out
    }
}
