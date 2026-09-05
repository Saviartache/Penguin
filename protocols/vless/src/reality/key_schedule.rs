//! Ключевое расписание TLS 1.3, RFC 8446 §7.1 — ровно тот кусок, что нужен,
//! чтобы дойти до ключа записи рукопожатия сервера: `Early Secret`, секрет
//! `derived`, `Handshake Secret`, секрет `s hs traffic`, ключ и `IV`.
//! Мастер-секрет и прикладные ключи сюда не входят — они не нужны для
//! проверки сертификата (`certificate.rs`), а дальше рукопожатие не ведётся
//! (см. `mod.rs`).
//!
//! ```text
//! 0 ──HKDF-Extract──> Early Secret
//!                          │
//!               Derive-Secret(.., "derived", "")
//!                          │
//!                          ▼
//! (EC)DHE ──HKDF-Extract──> Handshake Secret
//!                          │
//!         Derive-Secret(.., "s hs traffic", hash(CH..SH))
//!                          │
//!                          ▼
//!              server_handshake_traffic_secret
//!               │                        │
//!    HKDF-Expand-Label            HKDF-Expand-Label
//!      (.., "key", "", N)           (.., "iv", "", 12)
//!               │                        │
//!               ▼                        ▼
//!              key                       iv
//! ```
//!
//! Все три функции — `HKDF-Extract`, `HKDF-Expand-Label` и `Derive-Secret` —
//! названы в RFC 8446 §7.1 буквально этими формулами; здесь только их прямой
//! перевод на `ring::hkdf`, без ничего специфичного для Reality.
//!
//! Проверено на векторах RFC 8448 §3 ("Simple 1-RTT Handshake") — это не наш
//! формат и не формат Reality, а официальная трасса TLS 1.3 с промежуточными
//! значениями на каждом шаге, включая byte-in-byte `Handshake Secret` и ключ
//! записи сервера. Независимая проверка, а не круговой тест.

use ring::hkdf::{KeyType, Prk, Salt};

use crate::reality::cipher_suite::CipherSuite;
use crate::reality::error::RealityError;

/// Обёртка над длиной вывода — `ring::hkdf` просит тип, реализующий
/// [`KeyType`], а не голое число.
struct OutputLen(usize);

impl KeyType for OutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// `HKDF-Expand-Label` — RFC 8446 §7.1.
///
/// `HkdfLabel` — это `uint16 length`, затем `label` длиной 7..255 байт с
/// префиксом `"tls13 "`, затем `context` длиной 0..255 байт. Оба списка
/// заведомо короче своих ограничений: `label` здесь всегда одна из строк
/// ниже, `context` — не длиннее хеша транскрипта (32 или 48 байт).
fn expand_label(
    prk: &Prk,
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>, RealityError> {
    let full_label = format!("tls13 {label}");
    let mut hkdf_label = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    // `Okm` заимствует у `info` — временный массив с одним элементом не
    // пережил бы выражение, поэтому у него есть имя.
    let info: [&[u8]; 1] = [&hkdf_label];
    let okm = prk
        .expand(&info, OutputLen(length))
        .map_err(|_| RealityError::KeySchedule)?;
    let mut out = vec![0u8; length];
    okm.fill(&mut out).map_err(|_| RealityError::KeySchedule)?;
    Ok(out)
}

/// `Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label,
/// Transcript-Hash(Messages), Hash.length)` — RFC 8446 §7.1. `transcript` уже
/// хеширован вызывающим ([`transcript_hash`]).
fn derive_secret(
    cipher: CipherSuite,
    prk: &Prk,
    label: &str,
    transcript: &[u8],
) -> Result<Vec<u8>, RealityError> {
    expand_label(prk, label, transcript, cipher.hash_len())
}

/// Хеш транскрипта: конкатенация сообщений рукопожатия (без заголовков
/// TLS-записи, только заголовок и тело самого сообщения), пропущенная через
/// хеш этого шифра.
pub fn transcript_hash(cipher: CipherSuite, messages: &[&[u8]]) -> Vec<u8> {
    let mut ctx = ring::digest::Context::new(cipher.digest_algorithm());
    for message in messages {
        ctx.update(message);
    }
    ctx.finish().as_ref().to_vec()
}

/// Ключ и `IV` записи рукопожатия — одного направления (см. `record.rs`, где
/// эти же поля хранятся вместе с шифром и счётчиком записей).
pub struct HandshakeKeys {
    /// Ключ AEAD. Длина зависит от шифра — 16 байт для `AES-128-GCM`, 32 для
    /// двух остальных (`CipherSuite::key_len`).
    pub key: Vec<u8>,
    /// `IV`, из которого строится нонс каждой записи (`record.rs`).
    pub iv: [u8; 12],
}

/// Ключ и `IV`, которыми сервер шифрует `EncryptedExtensions`, `Certificate`,
/// `CertificateVerify` и свой `Finished`.
///
/// `dhe_shared_secret` — общий секрет `(EC)DHE` настоящего TLS 1.3, а не
/// `AuthKey` Reality (тот — с ключом Reality, этот — с ключом сервера из
/// `ServerHello`, см. `auth.rs`). `transcript_ch_sh` — хеш `ClientHello` и
/// `ServerHello`, посчитанный [`transcript_hash`] тем же шифром.
pub fn server_handshake_traffic_keys(
    cipher: CipherSuite,
    dhe_shared_secret: &[u8],
    transcript_ch_sh: &[u8],
) -> Result<HandshakeKeys, RealityError> {
    let alg = cipher.hkdf_algorithm();
    let hash_len = cipher.hash_len();
    let zeros = vec![0u8; hash_len];

    // Early Secret = HKDF-Extract(salt=0, ikm=0). PSK не используется — эта
    // реализация не ведёт возобновление сессии.
    let early_secret = Salt::new(alg, &zeros).extract(&zeros);

    // derived = Derive-Secret(EarlySecret, "derived", "") — "" транскрипта
    // здесь означает хеш ПУСТОЙ строки, а не пустой контекст.
    let empty_hash = transcript_hash(cipher, &[]);
    let derived = derive_secret(cipher, &early_secret, "derived", &empty_hash)?;

    // Handshake Secret = HKDF-Extract(salt=derived, ikm=(EC)DHE).
    let handshake_secret = Salt::new(alg, &derived).extract(dhe_shared_secret);

    let traffic_secret =
        derive_secret(cipher, &handshake_secret, "s hs traffic", transcript_ch_sh)?;
    let traffic_prk = Prk::new_less_safe(alg, &traffic_secret);

    let key = expand_label(&traffic_prk, "key", &[], cipher.key_len())?;
    let iv_bytes = expand_label(&traffic_prk, "iv", &[], 12)?;
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_bytes);

    Ok(HandshakeKeys { key, iv })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 8448 §3, "Simple 1-RTT Handshake": общий секрет `(EC)DHE` (там
    /// назван `IKM` шага "{server} extract secret \"handshake\"") и хеш
    /// `ClientHello`+`ServerHello` из этой же трассы дают ключ и `IV`,
    /// напечатанные на шаге "{server} derive write traffic keys for
    /// handshake data". Независимый источник — RFC, а не эталон Reality.
    #[test]
    fn server_handshake_keys_match_the_rfc_8448_test_vector() {
        let dhe_shared_secret = [
            0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63, 0xfd, 0xfb, 0xac, 0xf9, 0xf0, 0x4b,
            0x9f, 0x0d, 0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75, 0x63, 0xef, 0xd4, 0x62, 0x72, 0x90,
            0x0f, 0x89, 0x49, 0x2d,
        ];
        // Хеш ClientHello+ServerHello, напечатанный RFC на шаге "derive
        // secret \"tls13 c hs traffic\"" — тот же хеш нужен и для "s hs
        // traffic", RFC печатает его только один раз.
        let transcript = [
            0x86, 0x0c, 0x06, 0xed, 0xc0, 0x78, 0x58, 0xee, 0x8e, 0x78, 0xf0, 0xe7, 0x42, 0x8c,
            0x58, 0xed, 0xd6, 0xb4, 0x3f, 0x2c, 0xa3, 0xe6, 0xe9, 0x5f, 0x02, 0xed, 0x06, 0x3c,
            0xf0, 0xe1, 0xca, 0xd8,
        ];

        let keys = server_handshake_traffic_keys(
            CipherSuite::Aes128GcmSha256,
            &dhe_shared_secret,
            &transcript,
        )
        .expect("считается");

        assert_eq!(hex(&keys.key), "3fce516009c21727d0f2e4e86ee403bc");
        assert_eq!(hex(&keys.iv), "5d313eb2671276ee13000b30");
    }

    #[test]
    fn a_different_dhe_secret_gives_a_different_key() {
        let transcript = vec![0u8; 32];
        let a = server_handshake_traffic_keys(CipherSuite::Aes128GcmSha256, &[1; 32], &transcript)
            .expect("считается");
        let b = server_handshake_traffic_keys(CipherSuite::Aes128GcmSha256, &[2; 32], &transcript)
            .expect("считается");
        assert_ne!(a.key, b.key);
    }

    #[test]
    fn aes_256_keys_are_thirty_two_bytes_long() {
        let keys =
            server_handshake_traffic_keys(CipherSuite::Aes256GcmSha384, &[9; 32], &[0u8; 48])
                .expect("считается");
        assert_eq!(keys.key.len(), 32);
    }
}
