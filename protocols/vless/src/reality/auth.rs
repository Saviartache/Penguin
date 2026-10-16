//! Данные опознания Reality в 32 байтах `SessionID` и проверка сертификата сервера.
//!
//! Формат взят из `Xray-core` (`transport/internet/reality/reality.go`, `UClient`) и сверен с
//! `sing-box` (`common/tls/reality_client.go`); опубликованных векторов нет, о живой сервер
//! не проверено. `AuthKey = HKDF-SHA256(salt = client_random[..20], ikm = X25519 с ключом
//! Reality, info = "REALITY")` шифрует `SessionID` (AES-256-GCM) и заверяет сертификат (HMAC-SHA512).

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf::{self, KeyType};
use ring::hmac;

use crate::reality::error::RealityError;

/// Версия клиента в данных опознания: как у `sing-box` (`reality_client.go`), `1.8.1`.
/// Сервер сверяет её только при `minClientVer`/`maxClientVer`; строже — неотличимо от `NotRecognized`.
const CLIENT_VERSION: [u8; 3] = [1, 8, 1];

/// Данные опознания: версия(3) + резерв(1) + время(4) + `short_id`(8).
const PAYLOAD_LEN: usize = 16;

/// Данные опознания до шифрования (`reality.go`: `SessionId[0..3]` версия, `[3]` резерв,
/// `[4..8]` время BE, `[8..]` `ShortId`).
fn payload(short_id: [u8; 8], unix_time: u32) -> [u8; PAYLOAD_LEN] {
    let mut out = [0u8; PAYLOAD_LEN];
    out[0..3].copy_from_slice(&CLIENT_VERSION);
    out[4..8].copy_from_slice(&unix_time.to_be_bytes());
    out[8..16].copy_from_slice(&short_id);
    out
}

struct AuthKeyLen;

impl KeyType for AuthKeyLen {
    fn len(&self) -> usize {
        32
    }
}

/// Выводит `AuthKey`: `hkdf.New(sha256.New, secret, hello.Random[:20], "REALITY")`
/// в `reality.go` и `XTLS/reality` `tls.go`; общий секрет — `IKM`, `random[..20]` — соль.
pub fn derive_auth_key(
    shared_secret: &[u8; 32],
    client_random: &[u8; 32],
) -> Result<[u8; 32], RealityError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &client_random[..20]);
    let prk = salt.extract(shared_secret);
    let info: [&[u8]; 1] = [b"REALITY"];
    let okm = prk
        .expand(&info, AuthKeyLen)
        .map_err(|_| RealityError::KeySchedule)?;
    let mut out = [0u8; 32];
    okm.fill(&mut out).map_err(|_| RealityError::KeySchedule)?;
    Ok(out)
}

/// Шифрует данные опознания в `SessionID`: `AES-256-GCM(auth_key, nonce = random[20..32],
/// aad = ClientHello с нулевым SessionID)` (`reality.go`: `aead.Seal(hello.SessionId[:0],
/// hello.Random[20:], hello.SessionId[:16], hello.Raw)`); 16 байт шифротекста и 16 метки.
pub fn seal_session_id(
    auth_key: &[u8; 32],
    client_random: &[u8; 32],
    short_id: [u8; 8],
    unix_time: u32,
    client_hello_with_zero_session_id: &[u8],
) -> Result<[u8; 32], RealityError> {
    let plaintext = payload(short_id, unix_time);

    let unbound = UnboundKey::new(&aead::AES_256_GCM, auth_key)
        .map_err(|_| RealityError::Crypto("ключ AES-256-GCM"))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(&client_random[20..32])
        .map_err(|_| RealityError::Crypto("нонс AES-256-GCM"))?;

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        nonce,
        Aad::from(client_hello_with_zero_session_id),
        &mut in_out,
    )
    .map_err(|_| RealityError::Crypto("шифрование SessionID"))?;

    let mut out = [0u8; 32];
    out.copy_from_slice(&in_out);
    Ok(out)
}

/// Сертификат настоящий, если `HMAC-SHA512(AuthKey, subjectPublicKey) == signatureValue`
/// (`reality.go`, `VerifyPeerCertificate`; то же в `sing-box`); сравнение за постоянное время.
pub fn verify_certificate(
    auth_key: &[u8; 32],
    ed25519_public_key: &[u8; 32],
    signature: &[u8],
) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
    hmac::verify(&key, ed25519_public_key, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_layout_matches_the_documented_field_order() {
        let short_id = [0xAA; 8];
        let bytes = payload(short_id, 0x0102_0304);
        assert_eq!(&bytes[0..3], &CLIENT_VERSION);
        assert_eq!(bytes[3], 0, "резерв всегда нулевой");
        assert_eq!(&bytes[4..8], &0x0102_0304u32.to_be_bytes());
        assert_eq!(&bytes[8..16], &short_id);
    }

    #[test]
    fn deriving_the_auth_key_is_deterministic() {
        let secret = [7u8; 32];
        let random = [3u8; 32];
        let first = derive_auth_key(&secret, &random).expect("считается");
        let second = derive_auth_key(&secret, &random).expect("считается");
        assert_eq!(first, second);
    }

    #[test]
    fn a_different_client_random_changes_the_auth_key() {
        let secret = [7u8; 32];
        let a = derive_auth_key(&secret, &[1; 32]).expect("считается");
        let b = derive_auth_key(&secret, &[2; 32]).expect("считается");
        assert_ne!(a, b);
    }

    /// Круговой тест, без внешнего вектора: формат с живым сервером не сверен.
    #[test]
    fn sealing_the_session_id_round_trips_under_the_same_aead() {
        let auth_key = [9u8; 32];
        let client_random = [5u8; 32];
        let short_id = [0x11; 8];
        let unix_time = 1_700_000_000u32;
        let hello_with_zero_session_id = "клиентское приветствие с нулевым SessionID".as_bytes();
        let sealed = seal_session_id(
            &auth_key,
            &client_random,
            short_id,
            unix_time,
            hello_with_zero_session_id,
        )
        .expect("шифруется");
        assert_eq!(sealed.len(), 32);

        let unbound = UnboundKey::new(&aead::AES_256_GCM, &auth_key).expect("ключ верен");
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(&client_random[20..32]).expect("нонс верен");
        let mut in_out = sealed.to_vec();
        let opened = key
            .open_in_place(nonce, Aad::from(hello_with_zero_session_id), &mut in_out)
            .expect("расшифровывается тем же ключом");

        assert_eq!(opened, &payload(short_id, unix_time));
    }

    #[test]
    fn tampering_with_the_aad_breaks_decryption() {
        let auth_key = [9u8; 32];
        let client_random = [5u8; 32];
        let sealed =
            seal_session_id(&auth_key, &client_random, [0; 8], 0, b"hello-v1").expect("шифруется");

        let unbound = UnboundKey::new(&aead::AES_256_GCM, &auth_key).expect("ключ верен");
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(&client_random[20..32]).expect("нонс верен");
        let mut in_out = sealed.to_vec();
        assert!(
            key.open_in_place(nonce, Aad::from(b"hello-v2".as_ref()), &mut in_out)
                .is_err()
        );
    }

    /// RFC 4231 §4.2, Test Case 1 для HMAC-SHA-512.
    #[test]
    fn hmac_sha512_matches_the_rfc_4231_test_vector() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected: [u8; 64] = [
            0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d,
            0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05,
            0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b,
            0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70,
            0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54,
        ];
        let mac_key = hmac::Key::new(hmac::HMAC_SHA512, &key);
        assert!(hmac::verify(&mac_key, data, &expected).is_ok());
    }

    #[test]
    fn verify_certificate_uses_the_same_hmac_wiring() {
        let auth_key = [0x0b; 32];
        let pubkey = [0xAB; 32];
        let key = hmac::Key::new(hmac::HMAC_SHA512, &auth_key);
        let tag = hmac::sign(&key, &pubkey);
        assert!(verify_certificate(&auth_key, &pubkey, tag.as_ref()));

        let mut wrong = tag.as_ref().to_vec();
        wrong[0] ^= 1;
        assert!(!verify_certificate(&auth_key, &pubkey, &wrong));
    }
}
