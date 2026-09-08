//! Расшифровка одной записи рукопожатия TLS 1.3 — RFC 8446 §5.
//!
//! ```text
//! TLSCiphertext
//! ├─ тип записи (1)      = 0x17 (application_data — TLS 1.3 маскирует
//! │                        реальный тип содержимого им целиком, §5.1)
//! ├─ версия записи (2)   = 0x0303 (не значима, как в ClientHello)
//! ├─ длина (2)
//! └─ зашифрованное содержимое + метка AEAD
//!         │
//!         │  AEAD-Open(key, nonce = IV xor seq, aad = 5-байтный заголовок
//!         │             записи, ciphertext)
//!         ▼
//! TLSInnerPlaintext = content || тип содержимого (1) || нулевой padding
//! ```
//!
//! Нонс — RFC 8446 §5.3: `IV` (12 байт) поразрядно `xor` с восемью байтами
//! номера записи (big-endian, начиная с нуля), выровненными по правому краю.
//! Номер увеличивается на каждую успешно расшифрованную запись — но не на
//! `change_cipher_spec`, которая не шифруется вовсе (мидлбокс-совместимость
//! TLS 1.3, RFC 8446 Приложение D.4) и здесь просто пропускается тем, кто
//! читает записи ([`crate::reality::handshake`]).
//!
//! Проверено на RFC 8448 §3: настоящая зашифрованная запись сервера (679
//! октетов) расшифровывается ключом и `IV`, выведенными в
//! `key_schedule.rs`, — и результат совпадает байт в байт с открытым текстом
//! (`EncryptedExtensions` + `Certificate` + `CertificateVerify` + `Finished`),
//! который RFC печатает отдельно.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};

use crate::reality::cipher_suite::CipherSuite;
use crate::reality::error::RealityError;

/// Запись несёт сообщение рукопожатия (до шифрования) или замаскированное
/// под него содержимое (после — TLS 1.3 всегда шлёт `0x17` наружу).
pub const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
/// Заголовок записи снаружи у TLS 1.3 всегда этот, независимо от истинного
/// содержимого — оно названо только внутри, после расшифровки.
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;
/// `change_cipher_spec` — не шифруется, посылается только ради мидлбоксов,
/// ожидающих TLS 1.2, и не участвует в счётчике записей.
pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;

/// Ключ и `IV` одного направления вместе со счётчиком записей.
pub struct RecordKey {
    key: LessSafeKey,
    iv: [u8; 12],
    seq: u64,
}

impl RecordKey {
    /// Готовит ключ записи. `key_bytes`/`iv` — вывод
    /// [`crate::reality::key_schedule::server_handshake_traffic_keys`].
    pub fn new(cipher: CipherSuite, key_bytes: &[u8], iv: [u8; 12]) -> Result<Self, RealityError> {
        let unbound = UnboundKey::new(cipher.aead_algorithm(), key_bytes)
            .map_err(|_| RealityError::Crypto("ключ записи рукопожатия"))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            iv,
            seq: 0,
        })
    }

    /// Нонс текущей записи и продвижение счётчика — RFC 8446 §5.3.
    fn next_nonce(&mut self) -> Nonce {
        let mut nonce_bytes = self.iv;
        let seq_bytes = self.seq.to_be_bytes();
        for (byte, seq_byte) in nonce_bytes[4..].iter_mut().zip(seq_bytes) {
            *byte ^= seq_byte;
        }
        self.seq += 1;
        // `assume_unique_for_key` оправдан: нонс строится из счётчика,
        // который этот же метод и продвигает, — повтора не будет, пока
        // `RecordKey` не переживёт `u64::MAX` записей одного рукопожатия.
        Nonce::assume_unique_for_key(nonce_bytes)
    }

    /// Расшифровывает одну запись: `record_header` — 5 байт заголовка (AAD,
    /// RFC 8446 §5.2), `ciphertext_and_tag` — тело записи как пришло с
    /// провода. Возвращает настоящий тип содержимого и открытый текст без
    /// заполнения нулями.
    pub fn open(
        &mut self,
        record_header: &[u8; 5],
        ciphertext_and_tag: &mut [u8],
    ) -> Result<(u8, Vec<u8>), RealityError> {
        let nonce = self.next_nonce();
        let plaintext = self
            .key
            .open_in_place(
                nonce,
                Aad::from(record_header.as_slice()),
                ciphertext_and_tag,
            )
            .map_err(|_| RealityError::Crypto("запись рукопожатия не расшифровывается"))?;
        let (content_type, content) = split_inner_plaintext(plaintext)?;
        Ok((content_type, content.to_vec()))
    }

    /// Шифрует один кадр в TLS-запись — обратная операция к [`Self::open`],
    /// той же формулой (RFC 8446 §5.2): `TLSInnerPlaintext = content ||
    /// тип`, без набивки нулями (она нужна только для того, чтобы прятать
    /// длину, — здесь нечего прятать), затем `AEAD-Seal` с AAD из
    /// 5-байтного заголовка записи, который сам зависит от длины
    /// зашифрованного содержимого и потому собирается заранее.
    pub fn seal(&mut self, content_type: u8, plaintext: &[u8]) -> Result<Vec<u8>, RealityError> {
        let mut inner = Vec::with_capacity(plaintext.len() + 1);
        inner.extend_from_slice(plaintext);
        inner.push(content_type);

        let sealed_len = inner.len() + self.key.algorithm().tag_len();
        let mut header = [0u8; 5];
        header[0] = CONTENT_TYPE_APPLICATION_DATA;
        header[1..3].copy_from_slice(&[0x03, 0x03]);
        header[3..5].copy_from_slice(&(sealed_len as u16).to_be_bytes());

        let nonce = self.next_nonce();
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(header.as_slice()), &mut inner)
            .map_err(|_| RealityError::Crypto("шифрование прикладной записи"))?;

        let mut out = Vec::with_capacity(header.len() + inner.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&inner);
        Ok(out)
    }
}

/// Отделяет тип содержимого от заполнения нулями — RFC 8446 §5.4
/// (`TLSInnerPlaintext`): содержимое, потом ровно один байт типа, потом
/// сколько угодно (в том числе ноль) нулевых байт заполнения.
fn split_inner_plaintext(mut plaintext: &[u8]) -> Result<(u8, &[u8]), RealityError> {
    while let Some((0, rest)) = plaintext.split_last() {
        plaintext = rest;
    }
    let (&content_type, content) = plaintext
        .split_last()
        .ok_or(RealityError::Crypto("запись пуста после снятия заполнения"))?;
    Ok((content_type, content))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(hex: &str) -> Vec<u8> {
        let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).expect("тестовый хекс верен"))
            .collect()
    }

    #[test]
    fn inner_plaintext_strips_zero_padding_and_returns_the_real_type() {
        let plaintext = [1, 2, 3, CONTENT_TYPE_HANDSHAKE, 0, 0, 0];
        let (content_type, content) = split_inner_plaintext(&plaintext).expect("разбирается");
        assert_eq!(content_type, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(content, &[1, 2, 3]);
    }

    #[test]
    fn inner_plaintext_works_without_any_padding_too() {
        let plaintext = [9, 9, CONTENT_TYPE_APPLICATION_DATA];
        let (content_type, content) = split_inner_plaintext(&plaintext).expect("разбирается");
        assert_eq!(content_type, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(content, &[9, 9]);
    }

    #[test]
    fn an_all_zero_plaintext_has_no_content_type() {
        assert!(split_inner_plaintext(&[0, 0, 0]).is_err());
        assert!(split_inner_plaintext(&[]).is_err());
    }

    /// RFC 8448 §3: настоящая запись сервера (679 октетов на проводе, здесь
    /// без 5-байтного заголовка) расшифровывается ключом и `IV`, которые
    /// `key_schedule.rs` независимо вывел из той же трассы, и совпадает байт
    /// в байт с открытым текстом, который RFC печатает как "payload (657
    /// octets)": `EncryptedExtensions` + `Certificate` + `CertificateVerify`
    /// + `Finished`, за которыми следует один байт типа `0x16`.
    #[test]
    fn decrypts_the_rfc_8448_test_vector_record() {
        let key = from_hex("3fce516009c21727d0f2e4e86ee403bc");
        let iv_bytes = from_hex("5d313eb2671276ee13000b30");
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_bytes);

        let mut record_key =
            RecordKey::new(CipherSuite::Aes128GcmSha256, &key, iv).expect("ключ строится");

        let record_header: [u8; 5] = [0x17, 0x03, 0x03, 0x02, 0xa2];
        let mut ciphertext = from_hex(concat!(
            "d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f848a7ca0",
            "7612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5",
            "ecf7b13bd9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7477609aee6e12",
            "2a4cf51427325250c7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb3609872",
            "55cc744110c453baa4fcd610928d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead68",
            "6945ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b3684596c960bd596eea520a",
            "56a8d650f563aad27409960dca63d3e688611ea5e22f4415cf9538d51a200c27034272968a264ed6540c848",
            "38d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b659622245317b",
            "49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e1b7a6c7178af36879018e3f252",
            "107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cc",
            "a71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe5a376689",
            "36b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388c",
            "b5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b",
            "3b66763038ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c1233",
            "5ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5d2af939828fd4ae3794e44f94df5a631ede4",
            "2c1719bfdabf0253fe5175be898e750edc53370d2b",
        ));

        let (content_type, content) = record_key
            .open(&record_header, &mut ciphertext)
            .expect("расшифровывается");

        assert_eq!(content_type, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(content.len(), 657);

        let encrypted_extensions_start = 0;
        assert_eq!(content[encrypted_extensions_start], 0x08); // EncryptedExtensions
        let certificate_start = 40;
        assert_eq!(content[certificate_start], 0x0b); // Certificate
        let certificate_verify_start = certificate_start + 445;
        assert_eq!(content[certificate_verify_start], 0x0f); // CertificateVerify
        let finished_start = certificate_verify_start + 136;
        assert_eq!(content[finished_start], 0x14); // Finished
        assert_eq!(finished_start + 36, content.len());
    }

    #[test]
    fn a_tampered_record_is_refused_not_silently_accepted() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let mut record_key =
            RecordKey::new(CipherSuite::Aes128GcmSha256, &key, iv).expect("ключ строится");
        let header = [0x17, 0x03, 0x03, 0x00, 0x10];
        let mut garbage = vec![0xFFu8; 32];
        assert!(record_key.open(&header, &mut garbage).is_err());
    }

    /// RFC 8448 §3, "{client} send handshake record": клиентский `Finished`
    /// (36 октетов, тип `handshake` = `0x16`), зашифрованный клиентским
    /// ключом записи рукопожатия (тот же ключ и `IV`, что и в
    /// `key_schedule.rs`, `traffic_keys_matches_the_rfc_8448_client_handshake_vector`),
    /// даёт ровно ту запись, которую RFC печатает как "complete record (58
    /// octets)". Обратная сторона [`decrypts_the_rfc_8448_test_vector_record`]
    /// — там сервер шифрует, здесь клиент; независимая половина того же
    /// формата.
    #[test]
    fn seals_the_rfc_8448_client_finished_record() {
        let key = from_hex("db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01");
        let iv_bytes = from_hex("5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f");
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_bytes);
        let mut record_key =
            RecordKey::new(CipherSuite::Aes128GcmSha256, &key, iv).expect("ключ строится");

        let finished_message = from_hex(
            "14 00 00 20 a8 ec 43 6d 67 76 34 ae 52 5a c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9
             85 27 b6 42 f2 ed d5 ce 61",
        );

        let record = record_key
            .seal(CONTENT_TYPE_HANDSHAKE, &finished_message)
            .expect("шифруется");

        let expected = from_hex(
            "17 03 03 00 35 75 ec 4d c2 38 cc e6 0b 29 80 44 a7 1e 21 9c 56 cc 77 b0 51 7f e9
             b9 3c 7a 4b fc 44 d8 7f 38 f8 03 38 ac 98 fc 46 de b3 84 bd 1c ae ac ab 68 67 d7
             26 c4 05 46",
        );
        assert_eq!(record, expected);
    }

    #[test]
    fn what_is_sealed_can_be_opened_again() {
        let key = [3u8; 32];
        let iv = [4u8; 12];
        let mut sealer =
            RecordKey::new(CipherSuite::Chacha20Poly1305Sha256, &key, iv).expect("ключ строится");
        let mut opener =
            RecordKey::new(CipherSuite::Chacha20Poly1305Sha256, &key, iv).expect("ключ строится");

        for message in [b"first".as_slice(), b"second frame".as_slice()] {
            let mut record = sealer
                .seal(CONTENT_TYPE_APPLICATION_DATA, message)
                .expect("шифруется");
            let header: [u8; 5] = record[..5].try_into().expect("заголовок всегда 5 байт");
            let (content_type, opened) = opener
                .open(&header, &mut record[5..])
                .expect("расшифровывается");
            assert_eq!(content_type, CONTENT_TYPE_APPLICATION_DATA);
            assert_eq!(opened, message);
        }
    }
}
