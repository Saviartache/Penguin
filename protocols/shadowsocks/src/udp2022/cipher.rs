//! Разовые шифры одной датаграммы UDP 2022: нонс приходит из пакета, счётчика нет.
//!
//! AES-GCM: нонс (12 байт) — байты 4..16 заголовка пакета, ключ — подключ BLAKE3
//! из PSK и идентификатора сессии, сам заголовок шифруется отдельно одним блоком
//! AES на PSK уже после взятия нонса. Сверено с `shadowsocks-rust`
//! (`relay/udprelay/aead_2022.rs`) и `sing-shadowsocks2` (`shadowaead_2022/method.go`).
//!
//! ChaCha: `XChaCha20-Poly1305`, нонс 24 случайных байта едет перед пакетом,
//! PSK идёт в шифр как есть (`v2/udp/chacha20_poly1305.rs`).

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit as AesKeyInit};
use aes::{Aes128, Aes256, Block};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{Tag, XChaCha20Poly1305};
use ring::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

use crate::error::{ShadowsocksError, ShadowsocksResult};
use crate::method::Method2022;

/// Длина заголовка (идентификатор сессии + счётчик пакета): один блок AES.
pub const HEADER_LEN: usize = 16;

/// Длина нонса `XChaCha20`.
pub const CHACHA_NONCE_LEN: usize = 24;

/// Длина метки подлинности обоих шифров.
pub const TAG_LEN: usize = 16;

/// Шифрует тело на месте под явным нонсом, возвращает метку. Только AES-GCM.
pub fn aesgcm_seal(
    method: Method2022,
    key: &[u8],
    nonce12: &[u8],
    body: &mut [u8],
) -> ShadowsocksResult<[u8; TAG_LEN]> {
    let key = aesgcm_key(method, key)?;
    let tag = key
        .seal_in_place_separate_tag(aesgcm_nonce(nonce12)?, Aad::empty(), body)
        .map_err(|_| ShadowsocksError::crypto("датаграмма 2022 не шифруется"))?;
    tag.as_ref()
        .try_into()
        .map_err(|_| ShadowsocksError::crypto("метка AES-GCM не той длины"))
}

/// Расшифровывает тело (с меткой в конце) на месте, возвращает длину открытого текста.
pub fn aesgcm_open(
    method: Method2022,
    key: &[u8],
    nonce12: &[u8],
    body: &mut [u8],
) -> ShadowsocksResult<usize> {
    let key = aesgcm_key(method, key)?;
    key.open_in_place(aesgcm_nonce(nonce12)?, Aad::empty(), body)
        .map(|plain| plain.len())
        .map_err(|_| ShadowsocksError::Rejected)
}

fn aesgcm_nonce(nonce12: &[u8]) -> ShadowsocksResult<Nonce> {
    Nonce::try_assume_unique_for_key(nonce12)
        .map_err(|_| ShadowsocksError::crypto("нонс AES-GCM не той длины"))
}

fn aesgcm_key(method: Method2022, key: &[u8]) -> ShadowsocksResult<LessSafeKey> {
    let algorithm = match method {
        Method2022::Blake3Aes128Gcm => &AES_128_GCM,
        Method2022::Blake3Aes256Gcm => &AES_256_GCM,
        Method2022::Blake3Chacha20Poly1305 => {
            return Err(ShadowsocksError::crypto("метод не AES-GCM"));
        }
    };
    let unbound = UnboundKey::new(algorithm, key)
        .map_err(|_| ShadowsocksError::crypto("ключ AES-GCM не той длины"))?;
    Ok(LessSafeKey::new(unbound))
}

/// Шифрует заголовок пакета одним блоком AES прямо на PSK.
pub fn ecb_encrypt_header(
    method: Method2022,
    psk: &[u8],
    header: &mut [u8; HEADER_LEN],
) -> ShadowsocksResult<()> {
    aes_block(method, psk, header, true)
}

/// Расшифровывает заголовок, зашифрованный [`ecb_encrypt_header`].
pub fn ecb_decrypt_header(
    method: Method2022,
    psk: &[u8],
    header: &mut [u8; HEADER_LEN],
) -> ShadowsocksResult<()> {
    aes_block(method, psk, header, false)
}

fn aes_block(
    method: Method2022,
    psk: &[u8],
    header: &mut [u8; HEADER_LEN],
    encrypt: bool,
) -> ShadowsocksResult<()> {
    let mut block: Block = (*header).into();
    match method {
        Method2022::Blake3Aes128Gcm => {
            let cipher = Aes128::new_from_slice(psk)
                .map_err(|_| ShadowsocksError::crypto("ключ AES-128 не той длины"))?;
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
        }
        Method2022::Blake3Aes256Gcm => {
            let cipher = Aes256::new_from_slice(psk)
                .map_err(|_| ShadowsocksError::crypto("ключ AES-256 не той длины"))?;
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
        }
        Method2022::Blake3Chacha20Poly1305 => {
            return Err(ShadowsocksError::crypto("метод не AES-GCM"));
        }
    }
    header.copy_from_slice(&block);
    Ok(())
}

/// Шифрует пакет на месте под PSK как есть и нонсом, возвращает метку.
pub fn xchacha_seal(
    psk: &[u8],
    nonce24: &[u8; CHACHA_NONCE_LEN],
    plain: &mut [u8],
) -> ShadowsocksResult<[u8; TAG_LEN]> {
    let tag = xchacha(psk)?
        .encrypt_inout_detached(&(*nonce24).into(), b"", plain.into())
        .map_err(|_| ShadowsocksError::crypto("датаграмма 2022 не шифруется"))?;
    Ok(tag.into())
}

/// Расшифровывает пакет (с меткой в конце) на месте, возвращает длину открытого текста.
pub fn xchacha_open(
    psk: &[u8],
    nonce24: &[u8; CHACHA_NONCE_LEN],
    sealed: &mut [u8],
) -> ShadowsocksResult<usize> {
    let plain_len = sealed
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(ShadowsocksError::Rejected)?;
    let (body, tag) = sealed.split_at_mut(plain_len);
    let tag = Tag::try_from(&*tag).map_err(|_| ShadowsocksError::Rejected)?;
    xchacha(psk)?
        .decrypt_inout_detached(&(*nonce24).into(), b"", body.into(), &tag)
        .map_err(|_| ShadowsocksError::Rejected)?;
    Ok(plain_len)
}

/// Длина ключа проверяется сама: `GenericArray` на неверной длине паникует (AGENTS §4.3).
fn xchacha(psk: &[u8]) -> ShadowsocksResult<XChaCha20Poly1305> {
    let key: [u8; 32] = psk
        .try_into()
        .map_err(|_| ShadowsocksError::crypto("ключ ChaCha не той длины"))?;
    Ok(XChaCha20Poly1305::new(&key.into()))
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::XNonce;
    use chacha20poly1305::aead::{Aead as _, Payload};

    use super::*;

    fn hex_to_bytes(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("тестовый вектор верный"))
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn aes_128_ecb_matches_fips_197_appendix_c1() {
        // FIPS-197, C.1: проверяет подключение `aes`, а не наш вывод
        let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        let mut block: [u8; 16] = hex_to_bytes("00112233445566778899aabbccddeeff")
            .try_into()
            .expect("16 байт");

        ecb_encrypt_header(Method2022::Blake3Aes128Gcm, &key, &mut block).expect("шифруется");
        assert_eq!(hex(&block), "69c4e0d86a7b0430d8cdb78070b4c55a");

        ecb_decrypt_header(Method2022::Blake3Aes128Gcm, &key, &mut block)
            .expect("расшифровывается");
        assert_eq!(hex(&block), "00112233445566778899aabbccddeeff");
    }

    #[test]
    fn aes_256_ecb_matches_fips_197_appendix_c3() {
        let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let mut block: [u8; 16] = hex_to_bytes("00112233445566778899aabbccddeeff")
            .try_into()
            .expect("16 байт");

        ecb_encrypt_header(Method2022::Blake3Aes256Gcm, &key, &mut block).expect("шифруется");
        assert_eq!(hex(&block), "8ea2b7ca516745bfeafc49904b496089");
    }

    #[test]
    fn xchacha20poly1305_matches_the_draft_test_vector() {
        // draft-irtf-cfrg-xchacha, A.1, с непустым AAD: проверяет крейт, не нашу обёртку
        let key: [u8; 32] =
            hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .try_into()
                .expect("32 байта");
        let nonce: [u8; 24] = hex_to_bytes("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .expect("24 байта");
        let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let aead = XChaCha20Poly1305::new((&key).into());
        let xnonce: XNonce = nonce.into();
        let sealed = aead
            .encrypt(
                &xnonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("шифруется");

        let tag_at = sealed.len() - 16;
        assert_eq!(hex(&sealed[tag_at..]), "c0875924c1c7987947deafd8780acf49");
    }

    #[test]
    fn aesgcm_round_trips() {
        for method in [Method2022::Blake3Aes128Gcm, Method2022::Blake3Aes256Gcm] {
            let key = vec![7u8; method.key_len()];
            let nonce = [1u8; 12];
            let mut body = b"payload".to_vec();

            let tag = aesgcm_seal(method, &key, &nonce, &mut body).expect("шифруется");
            body.extend_from_slice(&tag);
            let len = aesgcm_open(method, &key, &nonce, &mut body).expect("расшифровывается");
            assert_eq!(&body[..len], b"payload");
        }
    }

    #[test]
    fn aesgcm_header_round_trips() {
        for method in [Method2022::Blake3Aes128Gcm, Method2022::Blake3Aes256Gcm] {
            let psk = vec![3u8; method.key_len()];
            let mut header = [0u8; HEADER_LEN];
            header[..8].copy_from_slice(&42u64.to_be_bytes());
            let original = header;

            ecb_encrypt_header(method, &psk, &mut header).expect("шифруется");
            assert_ne!(header, original);
            ecb_decrypt_header(method, &psk, &mut header).expect("расшифровывается");
            assert_eq!(header, original);
        }
    }

    fn xchacha_sealed(psk: &[u8; 32], nonce: &[u8; CHACHA_NONCE_LEN], plain: &[u8]) -> Vec<u8> {
        let mut out = plain.to_vec();
        let tag = xchacha_seal(psk, nonce, &mut out).expect("шифруется");
        out.extend_from_slice(&tag);
        out
    }

    #[test]
    fn xchacha_round_trips_with_our_empty_aad() {
        let psk = [5u8; 32];
        let nonce = [2u8; CHACHA_NONCE_LEN];
        let mut sealed = xchacha_sealed(&psk, &nonce, b"query");
        let len = xchacha_open(&psk, &nonce, &mut sealed).expect("расшифровывается");
        assert_eq!(&sealed[..len], b"query");
    }

    #[test]
    fn a_changed_byte_is_rejected() {
        let psk = [5u8; 32];
        let nonce = [2u8; CHACHA_NONCE_LEN];
        let mut sealed = xchacha_sealed(&psk, &nonce, b"query");
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(xchacha_open(&psk, &nonce, &mut sealed).is_err());
    }
}
