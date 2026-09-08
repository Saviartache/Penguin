//! Разовые шифры одной датаграммы UDP 2022 — без сети, без счётчика.
//!
//! У UDP 2022 нет растущего нонса: каждая датаграмма сама по себе, и нонс
//! либо считается из самого пакета (AES-GCM), либо бросается случайно и
//! едет на проводе целиком (ChaCha). Поэтому здесь не тот `Cipher`, что у
//! TCP ([`penguin_transport::aead::Cipher`], растущий счётчик), а разовые
//! операции с явным нонсом на каждый вызов.
//!
//! # AES-128/256-GCM
//!
//! Нонс (12 байт) — это байты 4..16 заголовка пакета (последние четыре байта
//! идентификатора сессии и весь счётчик пакета), а ключ AEAD — подключ,
//! выведенный BLAKE3 из PSK и идентификатора сессии ([`crate::kdf2022`]).
//! Сам заголовок (идентификатор сессии и счётчик, 16 байт) шифруется
//! отдельно — голым блоком AES прямо на PSK, без вывода: 16 байт — это
//! ровно один блок AES, дополнять нечем. Сверено построчно с
//! `shadowsocks-rust` (`relay/udprelay/aead_2022.rs::encrypt_message`,
//! `decrypt_message`) и `sing-shadowsocks2`
//! (`shadowaead_2022/method.go::WritePacket`, `readPacket`): оба шифруют
//! заголовок **после** того, как уже взяли из него (ещё открытого) нонс для
//! тела.
//!
//! # ChaCha20-Poly1305
//!
//! Здесь это не тело 2022, а `XChaCha20-Poly1305`: нонс 24 байта, случайный,
//! едет перед пакетом целиком, а PSK идёт в шифр как есть — сеансового
//! подключа нет вовсе. И это тоже проверено по обоим источникам:
//! `v2/udp/chacha20_poly1305.rs` берёт ключ параметром без вывода;
//! `method.go` строит `udpCipher` из `pskList[0]` один раз при создании
//! метода, до всякой сессии.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit as AesKeyInit};
use aes::{Aes128, Aes256, Block};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ring::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

use crate::error::{ShadowsocksError, ShadowsocksResult};
use crate::method::Method2022;

/// Длина заголовка (идентификатор сессии + счётчик пакета) — ровно один
/// блок AES, отсюда и раздельное шифрование.
pub const HEADER_LEN: usize = 16;

/// Длина явного нонса ChaCha20-Poly1305 (2022, UDP): `XChaCha20`, не обычный.
pub const CHACHA_NONCE_LEN: usize = 24;

/// Шифрует тело пакета (после 16-байтового заголовка) под явным 12-байтовым
/// нонсом и дописывает метку подлинности. Только для AES-128/256-GCM.
pub fn aesgcm_seal(
    method: Method2022,
    key: &[u8],
    nonce12: &[u8],
    body: &mut Vec<u8>,
) -> ShadowsocksResult<()> {
    let key = aesgcm_key(method, key)?;
    let nonce = Nonce::try_assume_unique_for_key(nonce12)
        .map_err(|_| ShadowsocksError::crypto("нонс AES-GCM не той длины"))?;
    key.seal_in_place_append_tag(nonce, Aad::empty(), body)
        .map_err(|_| ShadowsocksError::crypto("датаграмма 2022 не шифруется"))?;
    Ok(())
}

/// Расшифровывает тело на месте, возвращает длину открытого текста.
pub fn aesgcm_open(
    method: Method2022,
    key: &[u8],
    nonce12: &[u8],
    body: &mut [u8],
) -> ShadowsocksResult<usize> {
    let key = aesgcm_key(method, key)?;
    let nonce = Nonce::try_assume_unique_for_key(nonce12)
        .map_err(|_| ShadowsocksError::crypto("нонс AES-GCM не той длины"))?;
    let plain = key
        .open_in_place(nonce, Aad::empty(), body)
        .map_err(|_| ShadowsocksError::Rejected)?;
    Ok(plain.len())
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

/// Шифрует 16-байтовый заголовок пакета (идентификатор сессии + счётчик)
/// одним блоком AES прямо на PSK — без вывода подключа, без дополнения.
pub fn ecb_encrypt_header(
    method: Method2022,
    psk: &[u8],
    header: &mut [u8; HEADER_LEN],
) -> ShadowsocksResult<()> {
    let mut block: Block = (*header).into();
    match method {
        Method2022::Blake3Aes128Gcm => {
            let cipher = Aes128::new_from_slice(psk)
                .map_err(|_| ShadowsocksError::crypto("ключ AES-128 не той длины"))?;
            cipher.encrypt_block(&mut block);
        }
        Method2022::Blake3Aes256Gcm => {
            let cipher = Aes256::new_from_slice(psk)
                .map_err(|_| ShadowsocksError::crypto("ключ AES-256 не той длины"))?;
            cipher.encrypt_block(&mut block);
        }
        Method2022::Blake3Chacha20Poly1305 => {
            return Err(ShadowsocksError::crypto("метод не AES-GCM"));
        }
    }
    header.copy_from_slice(&block);
    Ok(())
}

/// Расшифровывает заголовок, зашифрованный [`ecb_encrypt_header`].
pub fn ecb_decrypt_header(
    method: Method2022,
    psk: &[u8],
    header: &mut [u8; HEADER_LEN],
) -> ShadowsocksResult<()> {
    let mut block: Block = (*header).into();
    match method {
        Method2022::Blake3Aes128Gcm => {
            let cipher = Aes128::new_from_slice(psk)
                .map_err(|_| ShadowsocksError::crypto("ключ AES-128 не той длины"))?;
            cipher.decrypt_block(&mut block);
        }
        Method2022::Blake3Aes256Gcm => {
            let cipher = Aes256::new_from_slice(psk)
                .map_err(|_| ShadowsocksError::crypto("ключ AES-256 не той длины"))?;
            cipher.decrypt_block(&mut block);
        }
        Method2022::Blake3Chacha20Poly1305 => {
            return Err(ShadowsocksError::crypto("метод не AES-GCM"));
        }
    }
    header.copy_from_slice(&block);
    Ok(())
}

/// Шифрует пакет целиком под PSK как есть и явным 24-байтовым нонсом.
pub fn xchacha_seal(
    psk: &[u8],
    nonce24: &[u8; CHACHA_NONCE_LEN],
    plaintext: &[u8],
) -> ShadowsocksResult<Vec<u8>> {
    let aead = XChaCha20Poly1305::new(&chacha_key(psk)?);
    let nonce: XNonce = (*nonce24).into();
    aead.encrypt(&nonce, plaintext)
        .map_err(|_| ShadowsocksError::crypto("датаграмма 2022 не шифруется"))
}

/// Расшифровывает то, что собрал [`xchacha_seal`].
pub fn xchacha_open(
    psk: &[u8],
    nonce24: &[u8; CHACHA_NONCE_LEN],
    ciphertext: &[u8],
) -> ShadowsocksResult<Vec<u8>> {
    let aead = XChaCha20Poly1305::new(&chacha_key(psk)?);
    let nonce: XNonce = (*nonce24).into();
    aead.decrypt(&nonce, ciphertext)
        .map_err(|_| ShadowsocksError::Rejected)
}

/// Ключ ChaCha20-Poly1305 из PSK — без вывода, но с проверкой длины: сама
/// `GenericArray` при неверной длине паникует, а на пути соединения нельзя
/// (`AGENTS.md` §4.3).
fn chacha_key(psk: &[u8]) -> ShadowsocksResult<chacha20poly1305::Key> {
    let bytes: [u8; 32] = psk
        .try_into()
        .map_err(|_| ShadowsocksError::crypto("ключ ChaCha не той длины"))?;
    Ok(bytes.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("тестовый вектор верный"))
            .collect()
    }

    /// Шестнадцатеричная запись — только для сверки с чужими значениями.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn aes_128_ecb_matches_fips_197_appendix_c1() {
        // FIPS-197, приложение C.1 — вектор про блочный AES-128 сам по
        // себе, не про Shadowsocks: проверяет, что `aes` подключён верно
        // (раскладка блока, порядок байт), а не наш собственный вывод.
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
        // Тот же источник, приложение C.3, ключ на 256 бит.
        let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let mut block: [u8; 16] = hex_to_bytes("00112233445566778899aabbccddeeff")
            .try_into()
            .expect("16 байт");

        ecb_encrypt_header(Method2022::Blake3Aes256Gcm, &key, &mut block).expect("шифруется");
        assert_eq!(hex(&block), "8ea2b7ca516745bfeafc49904b496089");
    }

    #[test]
    fn xchacha20poly1305_matches_the_draft_test_vector() {
        // draft-irtf-cfrg-xchacha, приложение A.1, через сам крейт
        // `chacha20poly1305` — с непустым AAD, которого наша обёртка
        // (`xchacha_seal`/`xchacha_open`) не использует вовсе. Подтверждает
        // крейт и раскладку ключа/нонса, а не саму обёртку — у неё ниже
        // отдельный круговой прогон.
        use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};

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

            aesgcm_seal(method, &key, &nonce, &mut body).expect("шифруется");
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

    #[test]
    fn xchacha_round_trips_with_our_empty_aad() {
        let psk = [5u8; 32];
        let nonce = [2u8; CHACHA_NONCE_LEN];
        let sealed = xchacha_seal(&psk, &nonce, b"query").expect("шифруется");
        let opened = xchacha_open(&psk, &nonce, &sealed).expect("расшифровывается");
        assert_eq!(opened, b"query");
    }

    #[test]
    fn a_changed_byte_is_rejected() {
        let psk = [5u8; 32];
        let nonce = [2u8; CHACHA_NONCE_LEN];
        let mut sealed = xchacha_seal(&psk, &nonce, b"query").expect("шифруется");
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(xchacha_open(&psk, &nonce, &sealed).is_err());
    }
}
