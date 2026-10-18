//! Конверт запроса к шлюзу (эталон — libagw `gateway/envelope.go`).
//!
//! AES-256 ключ (32 Б) и IV (32 Б, в CBC идут первые 16) шифруются ключом
//! шлюза по RSA PKCS#1 v1.5 и едут в `key_payload`; тело запроса шифруется
//! тем же AES-CBC и едет в `api_payload`. Ответ — сырой AES-CBC тем же
//! ключом и IV. Соль (8 Б) передаётся, но не используется — так ждёт сервер.

use aes::Aes256;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use penguin_core::base64;
use rand::rngs::OsRng;
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use serde::Serialize;

use crate::error::{SubscriptionError, SubscriptionResult};

type Encryptor = cbc::Encryptor<Aes256>;
type Decryptor = cbc::Decryptor<Aes256>;

const AES_KEY_LEN: usize = 32;
const AES_IV_LEN: usize = 32;
const AES_BLOCK: usize = 16;
const SALT_LEN: usize = 8;

/// Поля конверта как их ждёт сервер.
#[derive(Serialize)]
struct KeysPayload {
    aes_key: String,
    aes_iv: String,
    aes_salt: String,
}

/// Тело POST-запроса к шлюзу.
#[derive(Serialize)]
struct RequestBody {
    key_payload: String,
    api_payload: String,
}

/// Собранный запрос и AES-материал для расшифровки ответа.
pub struct Envelope {
    /// Готовое тело запроса (JSON).
    pub body: Vec<u8>,
    key: [u8; AES_KEY_LEN],
    iv: [u8; AES_IV_LEN],
}

impl Envelope {
    /// Расшифровывает ответ шлюза тем же ключом и IV.
    pub fn open(&self, ciphertext: &[u8]) -> SubscriptionResult<Vec<u8>> {
        aes_cbc_decrypt(ciphertext, &self.key, &self.iv)
    }
}

// Ключ и IV скрыты (`AGENTS.md` §5.2).
impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Envelope")
            .field("body", &self.body.len())
            .field("key", &"<скрыт>")
            .field("iv", &"<скрыт>")
            .finish()
    }
}

/// Шифрует тело запроса ключом шлюза (PKIX-PEM, `BEGIN PUBLIC KEY`).
pub fn seal(payload: &[u8], public_key_pem: &str) -> SubscriptionResult<Envelope> {
    let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .map_err(|e| SubscriptionError::Envelope(format!("ключ шлюза: {e}")))?;

    let mut key = [0u8; AES_KEY_LEN];
    let mut iv = [0u8; AES_IV_LEN];
    let mut salt = [0u8; SALT_LEN];
    for buffer in [&mut key[..], &mut iv[..], &mut salt[..]] {
        getrandom::fill(buffer).map_err(|e| SubscriptionError::Envelope(e.to_string()))?;
    }

    let keys_json = serde_json::to_vec(&KeysPayload {
        aes_key: base64::encode(&key),
        aes_iv: base64::encode(&iv),
        aes_salt: base64::encode(&salt),
    })
    .map_err(|e| SubscriptionError::Envelope(e.to_string()))?;

    let encrypted_keys = public_key
        .encrypt(&mut OsRng, rsa::Pkcs1v15Encrypt, &keys_json)
        .map_err(|e| SubscriptionError::Envelope(format!("RSA: {e}")))?;

    let ciphertext = aes_cbc_encrypt(payload, &key, &iv);

    let body = serde_json::to_vec(&RequestBody {
        key_payload: base64::encode(&encrypted_keys),
        api_payload: base64::encode(&ciphertext),
    })
    .map_err(|e| SubscriptionError::Envelope(e.to_string()))?;

    Ok(Envelope { body, key, iv })
}

/// Шифрует AES-256-CBC с дополнением PKCS#7; IV — первые 16 байт.
fn aes_cbc_encrypt(data: &[u8], key: &[u8; AES_KEY_LEN], iv: &[u8; AES_IV_LEN]) -> Vec<u8> {
    let iv16 = block_iv(iv);
    Encryptor::new(key.into(), (&iv16).into()).encrypt_padded_vec::<Pkcs7>(data)
}

/// Расшифровывает AES-256-CBC с дополнением PKCS#7; IV — первые 16 байт.
fn aes_cbc_decrypt(
    data: &[u8],
    key: &[u8; AES_KEY_LEN],
    iv: &[u8; AES_IV_LEN],
) -> SubscriptionResult<Vec<u8>> {
    if data.is_empty() || !data.len().is_multiple_of(AES_BLOCK) {
        return Err(SubscriptionError::Decrypt);
    }
    let iv16 = block_iv(iv);
    Decryptor::new(key.into(), (&iv16).into())
        .decrypt_padded_vec::<Pkcs7>(data)
        .map_err(|_| SubscriptionError::Decrypt)
}

/// Первые 16 байт переданного IV — ровно их берёт CBC.
fn block_iv(iv: &[u8; AES_IV_LEN]) -> [u8; AES_BLOCK] {
    let mut out = [0u8; AES_BLOCK];
    out.copy_from_slice(&iv[..AES_BLOCK]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;

    /// Внешний вектор AES-256-CBC/PKCS7 (`openssl enc -aes-256-cbc`).
    #[test]
    fn aes_matches_an_external_vector() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let mut iv = [0u8; 32];
        iv[..16].copy_from_slice(&std::array::from_fn::<u8, 16, _>(|i| i as u8));

        let plaintext = br#"{"service_type":"amnezia-premium"}"#;
        let expected = hex(
            "2d05accf3d82a9847944dd21205e7dd0bf353a1ebcac8ece6cdce6abba722a57\
             4e1cc79699a3f2f1a0dd8329a4dc07d6",
        );

        let got = aes_cbc_encrypt(plaintext, &key, &iv);
        assert_eq!(got, expected, "шифротекст разошёлся с openssl");

        let back = aes_cbc_decrypt(&expected, &key, &iv).expect("расшифровка");
        assert_eq!(back, plaintext);
    }

    #[test]
    fn a_short_or_ragged_response_does_not_decrypt() {
        let key = [7u8; 32];
        let iv = [9u8; 32];
        assert!(aes_cbc_decrypt(&[], &key, &iv).is_err());
        assert!(aes_cbc_decrypt(&[0u8; 20], &key, &iv).is_err());
    }

    #[test]
    fn the_envelope_round_trips_through_a_test_key() {
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("ключ");
        let public = private.to_public_key();
        let pem = public
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .expect("pem");

        let payload = br#"{"service_protocol":"awg"}"#;
        let envelope = seal(payload, &pem).expect("конверт");

        // Сервер: вскрыть key_payload своим приватным ключом, затем api_payload.
        let body: serde_json::Value = serde_json::from_slice(&envelope.body).expect("json");
        let key_payload = base64::decode(body["key_payload"].as_str().expect("поле")).expect("b64");
        let keys_json = private
            .decrypt(rsa::Pkcs1v15Encrypt, &key_payload)
            .expect("RSA");
        let keys: serde_json::Value = serde_json::from_slice(&keys_json).expect("json ключей");

        let key = to_array::<32>(&base64::decode(keys["aes_key"].as_str().unwrap()).unwrap());
        let mut iv = [0u8; 32];
        iv.copy_from_slice(&base64::decode(keys["aes_iv"].as_str().unwrap()).unwrap());
        let api_payload = base64::decode(body["api_payload"].as_str().expect("поле")).expect("b64");
        let decrypted = aes_cbc_decrypt(&api_payload, &key, &iv).expect("api");
        assert_eq!(decrypted, payload);

        // А окно вскроет ответ сервера (сырой AES-CBC) тем же конвертом.
        let response = aes_cbc_encrypt(br#"{"config":"vpn://x"}"#, &key, &iv);
        assert_eq!(
            envelope.open(&response).expect("ответ"),
            br#"{"config":"vpn://x"}"#
        );
    }

    #[test]
    fn a_bad_gateway_key_is_refused() {
        assert!(matches!(
            seal(b"{}", "не pem"),
            Err(SubscriptionError::Envelope(_))
        ));
    }

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        digits
            .chunks(2)
            .map(|pair| {
                let s = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(s, 16).unwrap()
            })
            .collect()
    }

    fn to_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        out
    }
}
