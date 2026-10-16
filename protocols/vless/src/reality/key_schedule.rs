//! Ключевое расписание TLS 1.3 (RFC 8446 §7.1) на `ring::hkdf`: от `Early Secret` до
//! прикладных ключей и `Finished`. Сверено с векторами RFC 8448 §3.

use ring::hkdf::{KeyType, Prk, Salt};
use ring::hmac;

use crate::reality::cipher_suite::CipherSuite;
use crate::reality::error::RealityError;

/// Длина вывода для `ring::hkdf`.
struct OutputLen(usize);

impl KeyType for OutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// `HKDF-Expand-Label` (RFC 8446 §7.1); метки и контекст заведомо короче 255 байт.
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

    let info: [&[u8]; 1] = [&hkdf_label];
    let okm = prk
        .expand(&info, OutputLen(length))
        .map_err(|_| RealityError::KeySchedule)?;
    let mut out = vec![0u8; length];
    okm.fill(&mut out).map_err(|_| RealityError::KeySchedule)?;
    Ok(out)
}

/// `Derive-Secret` с уже хешированным транскриптом (RFC 8446 §7.1).
fn derive_secret(
    cipher: CipherSuite,
    prk: &Prk,
    label: &str,
    transcript: &[u8],
) -> Result<Vec<u8>, RealityError> {
    expand_label(prk, label, transcript, cipher.hash_len())
}

/// Хеш транскрипта: сообщения рукопожатия без заголовков записей.
pub fn transcript_hash(cipher: CipherSuite, messages: &[&[u8]]) -> Vec<u8> {
    let mut ctx = ring::digest::Context::new(cipher.digest_algorithm());
    for message in messages {
        ctx.update(message);
    }
    ctx.finish().as_ref().to_vec()
}

/// Ключ AEAD и `IV` записи одного направления (RFC 8446 §7.3).
pub struct TrafficKeys {
    /// Ключ AEAD: 16 байт у `AES-128-GCM`, 32 у остальных.
    pub key: Vec<u8>,
    /// `IV`, из которого строится нонс записи.
    pub iv: [u8; 12],
}

/// Ключи, которыми сервер шифрует свой полёт: `dhe_shared_secret` — секрет `(EC)DHE` самого
/// TLS (не `AuthKey`), `transcript_ch_sh` — хеш `ClientHello..ServerHello`.
pub fn server_handshake_traffic_keys(
    cipher: CipherSuite,
    dhe_shared_secret: &[u8],
    transcript_ch_sh: &[u8],
) -> Result<TrafficKeys, RealityError> {
    let secret = handshake_secret(cipher, dhe_shared_secret)?
        .traffic_secret("s hs traffic", transcript_ch_sh)?;
    traffic_keys(cipher, &secret)
}

/// Ключ и `IV` из готового секрета трафика (рукопожатия или прикладного).
pub fn traffic_keys(cipher: CipherSuite, secret: &[u8]) -> Result<TrafficKeys, RealityError> {
    let prk = Prk::new_less_safe(cipher.hkdf_algorithm(), secret);
    let key = expand_label(&prk, "key", &[], cipher.key_len())?;
    let iv_bytes = expand_label(&prk, "iv", &[], 12)?;
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_bytes);
    Ok(TrafficKeys { key, iv })
}

/// `Handshake Secret`: источник секретов трафика рукопожатия и `Master Secret`.
pub struct HandshakeSecret {
    cipher: CipherSuite,
    prk: Prk,
}

/// `Early Secret` -> `derived` -> `HKDF-Extract` с `(EC)DHE` (RFC 8446 §7.1); PSK нет.
pub fn handshake_secret(
    cipher: CipherSuite,
    dhe_shared_secret: &[u8],
) -> Result<HandshakeSecret, RealityError> {
    let alg = cipher.hkdf_algorithm();
    let zeros = vec![0u8; cipher.hash_len()];

    let early_secret = Salt::new(alg, &zeros).extract(&zeros);
    let empty_hash = transcript_hash(cipher, &[]);
    let derived = derive_secret(cipher, &early_secret, "derived", &empty_hash)?;
    let prk = Salt::new(alg, &derived).extract(dhe_shared_secret);

    Ok(HandshakeSecret { cipher, prk })
}

impl HandshakeSecret {
    /// Секрет трафика рукопожатия: `label` — `"c hs traffic"` или `"s hs traffic"`.
    pub fn traffic_secret(
        &self,
        label: &str,
        transcript_ch_sh: &[u8],
    ) -> Result<Vec<u8>, RealityError> {
        derive_secret(self.cipher, &self.prk, label, transcript_ch_sh)
    }

    /// `Master Secret` (RFC 8446 §7.1).
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

/// `Master Secret`: исток прикладных секретов.
pub struct MasterSecret {
    cipher: CipherSuite,
    prk: Prk,
}

impl MasterSecret {
    /// Прикладной секрет: `label` — `"c ap traffic"` или `"s ap traffic"`. Транскрипт —
    /// `ClientHello..server Finished`: после `Finished` сервера, до `Finished` клиента.
    pub fn traffic_secret(
        &self,
        label: &str,
        transcript_ch_server_finished: &[u8],
    ) -> Result<Vec<u8>, RealityError> {
        derive_secret(self.cipher, &self.prk, label, transcript_ch_server_finished)
    }
}

/// `HMAC` на хеше шифра (RFC 8446 §4.4.4).
fn hmac_algorithm(cipher: CipherSuite) -> hmac::Algorithm {
    match cipher {
        CipherSuite::Aes128GcmSha256 | CipherSuite::Chacha20Poly1305Sha256 => hmac::HMAC_SHA256,
        CipherSuite::Aes256GcmSha384 => hmac::HMAC_SHA384,
    }
}

/// `finished_key` (RFC 8446 §4.4.4) из секрета трафика рукопожатия той стороны, чей `Finished`.
pub fn finished_key(cipher: CipherSuite, base_secret: &[u8]) -> Result<Vec<u8>, RealityError> {
    let prk = Prk::new_less_safe(cipher.hkdf_algorithm(), base_secret);
    expand_label(&prk, "finished", &[], cipher.hash_len())
}

/// `verify_data` своего `Finished`; чужой сверять через [`verify_finished`].
pub fn finished_verify_data(
    cipher: CipherSuite,
    finished_key: &[u8],
    transcript: &[u8],
) -> Vec<u8> {
    let key = hmac::Key::new(hmac_algorithm(cipher), finished_key);
    hmac::sign(&key, transcript).as_ref().to_vec()
}

/// Проверяет чужой `Finished` за постоянное время.
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

    /// RFC 8448 §3: ключ и `IV` шага "{server} derive write traffic keys for handshake data".
    #[test]
    fn server_handshake_keys_match_the_rfc_8448_test_vector() {
        let dhe_shared_secret = [
            0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63, 0xfd, 0xfb, 0xac, 0xf9, 0xf0, 0x4b,
            0x9f, 0x0d, 0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75, 0x63, 0xef, 0xd4, 0x62, 0x72, 0x90,
            0x0f, 0x89, 0x49, 0x2d,
        ];
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

    /// Общий секрет `(EC)DHE` из RFC 8448 §3.
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

    /// RFC 8448 §3: секреты "tls13 c hs traffic" и "tls13 s hs traffic" из одного `Handshake Secret`.
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

    /// RFC 8448 §3: секреты "tls13 c ap traffic" и "tls13 s ap traffic" с транскриптом до серверного `Finished`.
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

    /// RFC 8448 §3: "{server} derive write traffic keys for application data".
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

    /// RFC 8448 §3: "{server} derive read traffic keys for handshake data" (клиентский секрет).
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

    /// RFC 8448 §3: "{server} calculate finished".
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

    /// RFC 8448 §3: "{client} calculate finished", от секрета трафика до `verify_data`.
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
