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
use ring::hmac;

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

/// Ключ и `IV`, выведенные из произвольного секрета трафика —
/// `HKDF-Expand-Label(secret, "key"|"iv", "", ..)`, RFC 8446 §7.3. Та же
/// формула, что и в конце [`server_handshake_traffic_keys`], но не
/// привязана к секрету сервера времён рукопожатия: годится и для
/// клиентского секрета рукопожатия, и для прикладных секретов обеих сторон
/// ([`MasterSecret::traffic_secret`]) — довести рукопожатие до конца
/// (`handshake.rs`) без нужно во всех трёх случаях.
pub struct TrafficKeys {
    /// Ключ AEAD.
    pub key: Vec<u8>,
    /// `IV`, из которого строится нонс каждой записи (`record.rs`).
    pub iv: [u8; 12],
}

/// Выводит [`TrafficKeys`] из готового секрета трафика (не из общего
/// секрета `(EC)DHE`, как [`server_handshake_traffic_keys`], — секрет уже
/// выведен раньше, этот шаг только превращает его в ключ и `IV`).
pub fn traffic_keys(cipher: CipherSuite, secret: &[u8]) -> Result<TrafficKeys, RealityError> {
    let prk = Prk::new_less_safe(cipher.hkdf_algorithm(), secret);
    let key = expand_label(&prk, "key", &[], cipher.key_len())?;
    let iv_bytes = expand_label(&prk, "iv", &[], 12)?;
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_bytes);
    Ok(TrafficKeys { key, iv })
}

/// `Handshake Secret` вместе с тем, что из него выводится дальше: секретами
/// трафика обеих сторон рукопожатия ([`Self::traffic_secret`]) и, ещё одним
/// `Derive-Secret(.., "derived", "")`, — `Master Secret`
/// ([`Self::master_secret`]). RFC 8446 §7.1 передаёт этот секрет от шага к
/// шагу как одно значение; [`server_handshake_traffic_keys`] использует его
/// один раз и не отдаёт наружу — доводя рукопожатие до `Finished`, он нужен
/// вызывающему ещё дважды (свой `Finished`, прикладные ключи), и держать
/// его негде, кроме как в этом типе.
pub struct HandshakeSecret {
    cipher: CipherSuite,
    prk: Prk,
}

/// Выводит `Handshake Secret` — RFC 8446 §7.1: `Early Secret`, `derived`,
/// затем `HKDF-Extract` с общим секретом `(EC)DHE` в качестве `IKM`. Те же
/// три шага, что уже сверены байт в байт с RFC 8448 §3 внутри
/// [`server_handshake_traffic_keys`] (см. его тест) — здесь та же формула
/// ради секрета, который вызывающий может использовать больше одного раза.
pub fn handshake_secret(
    cipher: CipherSuite,
    dhe_shared_secret: &[u8],
) -> Result<HandshakeSecret, RealityError> {
    let alg = cipher.hkdf_algorithm();
    let hash_len = cipher.hash_len();
    let zeros = vec![0u8; hash_len];

    let early_secret = Salt::new(alg, &zeros).extract(&zeros);
    let empty_hash = transcript_hash(cipher, &[]);
    let derived = derive_secret(cipher, &early_secret, "derived", &empty_hash)?;
    let prk = Salt::new(alg, &derived).extract(dhe_shared_secret);

    Ok(HandshakeSecret { cipher, prk })
}

impl HandshakeSecret {
    /// Секрет трафика одного направления рукопожатия —
    /// `Derive-Secret(HandshakeSecret, label, hash(ClientHello..ServerHello))`.
    /// `label` — `"c hs traffic"` или `"s hs traffic"`.
    pub fn traffic_secret(
        &self,
        label: &str,
        transcript_ch_sh: &[u8],
    ) -> Result<Vec<u8>, RealityError> {
        derive_secret(self.cipher, &self.prk, label, transcript_ch_sh)
    }

    /// `Master Secret = HKDF-Extract(salt=Derive-Secret(HandshakeSecret,
    /// "derived", ""), ikm=0)` — RFC 8446 §7.1.
    pub fn master_secret(&self) -> Result<MasterSecret, RealityError> {
        let empty_hash = transcript_hash(self.cipher, &[]);
        let derived = derive_secret(self.cipher, &self.prk, "derived", &empty_hash)?;
        let zeros = vec![0u8; self.cipher.hash_len()];
        let prk = Salt::new(self.cipher.hkdf_algorithm(), &derived).extract(&zeros);
        Ok(MasterSecret {
            cipher: self.cipher,
            prk,
        })
    }
}

/// `Master Secret` — исток прикладных секретов трафика (RFC 8446 §7.1).
pub struct MasterSecret {
    cipher: CipherSuite,
    prk: Prk,
}

impl MasterSecret {
    /// Прикладной секрет трафика одного направления —
    /// `Derive-Secret(MasterSecret, label, hash(ClientHello..server Finished))`.
    /// `label` — `"c ap traffic"` или `"s ap traffic"`.
    ///
    /// **Ловушка (см. `mod.rs`):** транскрипт здесь берётся ДО `Finished`
    /// клиента, но ПОСЛЕ `Finished` сервера — RFC 8446 §7.1 подписывает эту
    /// ветку диаграммы как `ClientHello...server Finished`, а не «до обоих
    /// `Finished`». Секрет, выведенный с транскриптом до серверного
    /// `Finished` или после клиентского, не совпадёт с тем, что вывел
    /// сервер, — и результат неотличим на этом шаге от битых ключей: канал
    /// откроется, а расшифровать хотя бы один байт не удастся.
    pub fn traffic_secret(
        &self,
        label: &str,
        transcript_ch_server_finished: &[u8],
    ) -> Result<Vec<u8>, RealityError> {
        derive_secret(self.cipher, &self.prk, label, transcript_ch_server_finished)
    }
}

/// Алгоритм `HMAC` ключевого расписания — тот же хеш, что и у `HKDF` этого
/// шифра (RFC 8446 §7.1: `Finished` считается хеш-функцией рукопожатия, не
/// отдельно назначенной).
fn hmac_algorithm(cipher: CipherSuite) -> hmac::Algorithm {
    match cipher {
        CipherSuite::Aes128GcmSha256 | CipherSuite::Chacha20Poly1305Sha256 => hmac::HMAC_SHA256,
        CipherSuite::Aes256GcmSha384 => hmac::HMAC_SHA384,
    }
}

/// `finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)`
/// — RFC 8446 §4.4.4. `base_secret` — секрет трафика рукопожатия той
/// стороны, чей `Finished` считается ([`HandshakeSecret::traffic_secret`]).
pub fn finished_key(cipher: CipherSuite, base_secret: &[u8]) -> Result<Vec<u8>, RealityError> {
    let prk = Prk::new_less_safe(cipher.hkdf_algorithm(), base_secret);
    expand_label(&prk, "finished", &[], cipher.hash_len())
}

/// `verify_data = HMAC(finished_key, Transcript-Hash(...))` — RFC 8446
/// §4.4.4, направление «посчитать свой `Finished`». Сравнение чужого
/// значения — отдельно, [`verify_finished`]: оно должно быть постоянным по
/// времени, а не через `==` на возвращённый отсюда вектор.
pub fn finished_verify_data(
    cipher: CipherSuite,
    finished_key: &[u8],
    transcript: &[u8],
) -> Vec<u8> {
    let key = hmac::Key::new(hmac_algorithm(cipher), finished_key);
    hmac::sign(&key, transcript).as_ref().to_vec()
}

/// Проверяет чужой `Finished` — постоянное по времени сравнение
/// ([`ring::hmac::verify`]), а не пересчёт через [`finished_verify_data`] и
/// побайтовое `==`.
pub fn verify_finished(
    cipher: CipherSuite,
    finished_key: &[u8],
    transcript: &[u8],
    received_verify_data: &[u8],
) -> bool {
    let key = hmac::Key::new(hmac_algorithm(cipher), finished_key);
    hmac::verify(&key, transcript, received_verify_data).is_ok()
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

    fn from_hex(hex: &str) -> Vec<u8> {
        let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).expect("тестовый хекс верен"))
            .collect()
    }

    /// Общий секрет `(EC)DHE` из RFC 8448 §3 — тот же, что и в
    /// [`server_handshake_keys_match_the_rfc_8448_test_vector`].
    fn rfc_8448_dhe_shared_secret() -> Vec<u8> {
        from_hex(
            "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90
             0f 89 49 2d",
        )
    }

    /// Хеш `ClientHello`+`ServerHello` из той же трассы.
    fn rfc_8448_transcript_ch_sh() -> Vec<u8> {
        from_hex(
            "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c
             f0 e1 ca d8",
        )
    }

    /// RFC 8448 §3, шаги "{server} derive secret \"tls13 c hs traffic\"" и
    /// "tls13 s hs traffic": оба секрета трафика рукопожатия выводятся из
    /// одного и того же `Handshake Secret` — независимая проверка того, что
    /// [`HandshakeSecret`] действительно даёт использовать его дважды, а не
    /// только для секрета сервера, как [`server_handshake_traffic_keys`].
    #[test]
    fn handshake_secret_yields_both_traffic_secrets_from_the_rfc_8448_vector() {
        let secret = handshake_secret(CipherSuite::Aes128GcmSha256, &rfc_8448_dhe_shared_secret())
            .expect("считается");
        let transcript = rfc_8448_transcript_ch_sh();

        let client = secret
            .traffic_secret("c hs traffic", &transcript)
            .expect("считается");
        let server = secret
            .traffic_secret("s hs traffic", &transcript)
            .expect("считается");

        assert_eq!(
            client,
            from_hex(
                "b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74
                 6a 0e 27 a5 5a 21"
            )
        );
        assert_eq!(
            server,
            from_hex(
                "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be
                 fd 59 d3 91 ad 38"
            )
        );
    }

    /// RFC 8448 §3, "{server} derive secret \"tls13 c ap traffic\"" и
    /// "tls13 s ap traffic": транскрипт здесь — это хеш `ClientHello`
    /// вплоть до серверного `Finished` (см. `finished_verify_data`, тот же
    /// хеш используется как сообщение HMAC для `Finished` клиента). Это и
    /// есть ловушка из документа модуля — секреты выводятся ДО `Finished`
    /// клиента, но ПОСЛЕ `Finished` сервера.
    #[test]
    fn master_secret_yields_both_application_traffic_secrets_from_the_rfc_8448_vector() {
        let handshake =
            handshake_secret(CipherSuite::Aes128GcmSha256, &rfc_8448_dhe_shared_secret())
                .expect("считается");
        let master = handshake.master_secret().expect("считается");
        let transcript_through_server_finished = from_hex(
            "96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a 00 0e aa da 3d aa e4 77 7a 76 86
             c9 ff 83 df 13",
        );

        let client = master
            .traffic_secret("c ap traffic", &transcript_through_server_finished)
            .expect("считается");
        let server = master
            .traffic_secret("s ap traffic", &transcript_through_server_finished)
            .expect("считается");

        assert_eq!(
            client,
            from_hex(
                "9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00 87 f7 92
                 eb b7 c1 75 04 a5"
            )
        );
        assert_eq!(
            server,
            from_hex(
                "a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f
                 1f 3f cb 63 16 43"
            )
        );
    }

    /// RFC 8448 §3, "{server} derive write traffic keys for application
    /// data": ключ и `IV`, выведенные тем же [`traffic_keys`], что и
    /// клиентские ключи рукопожатия ниже, — общая формула для любого
    /// секрета трафика, не только для секрета сервера времён рукопожатия.
    #[test]
    fn traffic_keys_matches_the_rfc_8448_server_application_data_vector() {
        let server_ap_traffic_secret = from_hex(
            "a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f
             3f cb 63 16 43",
        );
        let keys = traffic_keys(CipherSuite::Aes128GcmSha256, &server_ap_traffic_secret)
            .expect("считается");
        assert_eq!(
            keys.key,
            from_hex("9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac 92 e3 56")
        );
        assert_eq!(
            keys.iv,
            from_hex("cf 78 2b 88 dd 83 54 9a ad f1 e9 84").as_slice()
        );
    }

    /// RFC 8448 §3, "{server} derive read traffic keys for handshake
    /// data": то, чем сервер читает `Finished` клиента, — то же самое, чем
    /// клиент его пишет. Проверяет [`traffic_keys`] на клиентском секрете
    /// рукопожатия (а не только на серверном, как
    /// [`server_handshake_traffic_keys`]).
    #[test]
    fn traffic_keys_matches_the_rfc_8448_client_handshake_vector() {
        let client_hs_traffic_secret = from_hex(
            "b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a
             0e 27 a5 5a 21",
        );
        let keys = traffic_keys(CipherSuite::Aes128GcmSha256, &client_hs_traffic_secret)
            .expect("считается");
        assert_eq!(
            keys.key,
            from_hex("db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01")
        );
        assert_eq!(
            keys.iv,
            from_hex("5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f").as_slice()
        );
    }

    /// RFC 8448 §3, "{server} calculate finished \"tls13 finished\"":
    /// `finished_key` сервера — тот же секрет трафика, тот же пустой
    /// контекст, что печатает RFC.
    #[test]
    fn finished_key_matches_the_rfc_8448_server_vector() {
        let server_hs_traffic_secret = from_hex(
            "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd
             59 d3 91 ad 38",
        );
        let key = finished_key(CipherSuite::Aes128GcmSha256, &server_hs_traffic_secret)
            .expect("считается");
        assert_eq!(
            key,
            from_hex(
                "00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85 c3 1f c0 68 bf 49 2c 65 2f 01 f2 88
                 a1 d8 cd c1 9f c8"
            )
        );
    }

    /// RFC 8448 §3, "{client} calculate finished \"tls13 finished\"": и
    /// `finished_key`, и итоговый `verify_data` клиента — из транскрипта,
    /// который [`master_secret_yields_both_application_traffic_secrets_from_the_rfc_8448_vector`]
    /// уже использовал для прикладных секретов (RFC печатает его только
    /// один раз, но использует дважды, — здесь то же самое). Сквозная
    /// проверка [`finished_key`] и [`finished_verify_data`]/[`verify_finished`]
    /// вместе, от секрета трафика до итоговых 32 байт `Finished`.
    #[test]
    fn finished_verify_data_matches_the_rfc_8448_client_vector() {
        let client_hs_traffic_secret = from_hex(
            "b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a
             0e 27 a5 5a 21",
        );
        let transcript_through_server_finished = from_hex(
            "96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a 00 0e aa da 3d aa e4 77 7a 76 86
             c9 ff 83 df 13",
        );
        let expected_finished_key = from_hex(
            "b8 0a d0 10 15 fb 2f 0b d6 5f f7 d4 da 5d 6b f8 3f 84 82 1d 1f 87 fd c7 d3 c7 5b
             5a 7b 42 d9 c4",
        );
        let expected_verify_data = from_hex(
            "a8 ec 43 6d 67 76 34 ae 52 5a c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42
             f2 ed d5 ce 61",
        );

        let key = finished_key(CipherSuite::Aes128GcmSha256, &client_hs_traffic_secret)
            .expect("считается");
        assert_eq!(key, expected_finished_key);

        let verify_data = finished_verify_data(
            CipherSuite::Aes128GcmSha256,
            &key,
            &transcript_through_server_finished,
        );
        assert_eq!(verify_data, expected_verify_data);
        assert!(verify_finished(
            CipherSuite::Aes128GcmSha256,
            &key,
            &transcript_through_server_finished,
            &expected_verify_data
        ));
    }

    #[test]
    fn verify_finished_rejects_a_tampered_verify_data() {
        let key = finished_key(CipherSuite::Aes128GcmSha256, &[7u8; 32]).expect("считается");
        let transcript = [0u8; 32];
        let genuine = finished_verify_data(CipherSuite::Aes128GcmSha256, &key, &transcript);
        let mut tampered = genuine.clone();
        tampered[0] ^= 1;
        assert!(verify_finished(
            CipherSuite::Aes128GcmSha256,
            &key,
            &transcript,
            &genuine
        ));
        assert!(!verify_finished(
            CipherSuite::Aes128GcmSha256,
            &key,
            &transcript,
            &tampered
        ));
    }
}
