//! `ClientHello` каждого отпечатка глазами сервера `XTLS/REALITY` (`tls.go`, `Server`):
//! разбор `key_share` по `clientHelloMsg.unmarshal`, выбор ключа, `AuthKey` и `aead.Open`
//! над `clientHello.original` с нулевым `SessionID`. Сервер повторён по исходнику, живого нет.

#![allow(clippy::expect_used)]

use penguin_utls::Fingerprint;
use penguin_vless::reality::RealityConfig;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral};
use ring::hkdf;
use tokio::io::AsyncReadExt;

/// `tls.go`: группы, которые сервер REALITY повторяет за сайтом-прикрытием.
const X25519_GROUP: u16 = 29;
const X25519_MLKEM768: u16 = 4588;
/// `mlkem.EncapsulationKeySize768`.
const MLKEM768_ENCAPSULATION_KEY_LEN: usize = 1184;

const SHORT_ID: [u8; 8] = [0x12, 0x34, 0, 0, 0, 0, 0, 0];

struct Hello {
    message: Vec<u8>,
    random: [u8; 32],
    session_id_at: usize,
    key_shares: Vec<(u16, Vec<u8>)>,
}

fn u16_at(data: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([data[at], data[at + 1]])
}

/// Поля `clientHelloMsg.unmarshal`, нужные `tls.go`.
fn parse(message: Vec<u8>) -> Hello {
    let random: [u8; 32] = message[6..38].try_into().expect("random");
    let session_id_at = 39;
    assert_eq!(message[38], 32, "SessionID — 32 байта");
    let mut at = session_id_at + 32;
    at += 2 + usize::from(u16_at(&message, at));
    at += 1 + usize::from(message[at]);
    let extensions_end = at + 2 + usize::from(u16_at(&message, at));
    assert_eq!(extensions_end, message.len());
    at += 2;
    let mut key_shares = Vec::new();
    while at < extensions_end {
        let (kind, len) = (u16_at(&message, at), usize::from(u16_at(&message, at + 2)));
        let body = &message[at + 4..at + 4 + len];
        if kind == 51 {
            let mut entry = 2;
            while entry < body.len() {
                let data_len = usize::from(u16_at(body, entry + 2));
                let data = body[entry + 4..entry + 4 + data_len].to_vec();
                key_shares.push((u16_at(body, entry), data));
                entry += 4 + data_len;
            }
        }
        at += 4 + len;
    }
    Hello {
        message,
        random,
        session_id_at,
        key_shares,
    }
}

/// Цикл `for _, keyShare := range hs.clientHello.keyShares` из `tls.go`.
fn reality_peer_key(key_shares: &[(u16, Vec<u8>)]) -> Option<Vec<u8>> {
    let (mut peer, mut peer_from_hybrid) = (None, None);
    for (group, data) in key_shares {
        if *group == X25519_MLKEM768 && data.len() == MLKEM768_ENCAPSULATION_KEY_LEN + 32 {
            if peer_from_hybrid.is_some() {
                return None;
            }
            peer_from_hybrid = Some(data[MLKEM768_ENCAPSULATION_KEY_LEN..].to_vec());
            continue;
        }
        if *group == X25519_GROUP && data.len() == 32 {
            if peer.is_some() {
                return None;
            }
            peer = Some(data.clone());
            break;
        }
    }
    peer_from_hybrid.as_ref()?;
    peer.or(peer_from_hybrid)
}

struct AuthKeyLen;

impl hkdf::KeyType for AuthKeyLen {
    fn len(&self) -> usize {
        32
    }
}

/// `AuthKey` и `aead.Open(..., hs.clientHello.original)`; `None` — сервер ответит сайтом-прикрытием.
fn open_session_id(hello: &Hello, server_key: EphemeralPrivateKey) -> Option<[u8; 16]> {
    let peer = reality_peer_key(&hello.key_shares)?;
    let shared = agree_ephemeral(server_key, &UnparsedPublicKey::new(&X25519, peer), |s| {
        s.to_vec()
    })
    .ok()?;
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &hello.random[..20]);
    let mut auth_key = [0u8; 32];
    salt.extract(&shared)
        .expand(&[b"REALITY"], AuthKeyLen)
        .ok()?
        .fill(&mut auth_key)
        .ok()?;

    let session_id = hello.session_id_at..hello.session_id_at + 32;
    let mut sealed = hello.message[session_id.clone()].to_vec();
    let mut original = hello.message.clone();
    original[session_id].fill(0);
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &auth_key).ok()?);
    let nonce = Nonce::try_assume_unique_for_key(&hello.random[20..]).ok()?;
    let plain = key
        .open_in_place(nonce, Aad::from(&original), &mut sealed)
        .ok()?;
    plain.try_into().ok()
}

async fn client_hello(fingerprint: Fingerprint, server_public: &[u8]) -> Vec<u8> {
    let config = RealityConfig {
        public_key: penguin_core::base64::encode_url(server_public),
        short_id: "1234".to_owned(),
        server_name: "www.example.com".to_owned(),
        fingerprint,
    };
    let (mut client, mut server) = tokio::io::duplex(1 << 16);
    let handshake = tokio::spawn(async move {
        let _ = penguin_vless::reality::verify(&mut client, &config).await;
    });
    let mut header = [0u8; 5];
    server
        .read_exact(&mut header)
        .await
        .expect("заголовок записи");
    let mut message = vec![0u8; usize::from(u16_at(&header, 3))];
    server.read_exact(&mut message).await.expect("ClientHello");
    drop(server);
    handshake.await.expect("задача");
    message
}

#[tokio::test]
async fn reality_server_opens_the_session_id_of_every_fingerprint() {
    for fingerprint in [
        Fingerprint::Chrome,
        Fingerprint::Firefox,
        Fingerprint::Safari,
    ] {
        let rng = ring::rand::SystemRandom::new();
        let server_key = EphemeralPrivateKey::generate(&X25519, &rng).expect("ключ");
        let server_public = server_key.compute_public_key().expect("публичный");
        let hello = parse(client_hello(fingerprint, server_public.as_ref()).await);
        let plain = open_session_id(&hello, server_key)
            .unwrap_or_else(|| panic!("{fingerprint:?}: REALITY не узнал бы клиента"));
        assert_eq!(&plain[8..], &SHORT_ID, "{fingerprint:?}");
    }
}

/// `tls.go` принимает `ServerHello` сайта-прикрытия только с `X25519` или `X25519MLKEM768`;
/// иначе — отдаёт клиенту сам сайт. Лишняя запись `key_share` позволяет сайту выбрать её.
#[tokio::test]
async fn every_key_share_is_one_reality_can_follow() {
    let rng = ring::rand::SystemRandom::new();
    let server_key = EphemeralPrivateKey::generate(&X25519, &rng).expect("ключ");
    let server_public = server_key.compute_public_key().expect("публичный");
    for fingerprint in [
        Fingerprint::Chrome,
        Fingerprint::Firefox,
        Fingerprint::Safari,
    ] {
        let hello = parse(client_hello(fingerprint, server_public.as_ref()).await);
        for (group, data) in &hello.key_shares {
            let grease = penguin_utls::grease::is_grease(*group) && data.len() == 1;
            assert!(
                grease || [X25519_GROUP, X25519_MLKEM768].contains(group),
                "{fingerprint:?}: группа {group:#06x} в key_share"
            );
        }
    }
}
