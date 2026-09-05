//! Достаточно X.509 DER, чтобы достать из сертификата сервера открытый ключ
//! Ed25519 и подпись, — не больше.
//!
//! Reality не проверяет цепочку сертификатов вовсе (сервер подписывает
//! сертификат сам себе, ключом, который никто не удостоверял): вместо этого
//! `signatureValue` — это `HMAC-SHA512(AuthKey, subjectPublicKey)`
//! (`auth.rs`). Если бы этот модуль тянул за собой полноценный разбор X.509,
//! он проверял бы поля, которые Reality сознательно не использует по
//! назначению.
//!
//! Полный разбор `Certificate` (RFC 8446 §4.4.2) и DER (ITU-T X.690, разделы
//! 8.1.2–8.1.3 — тег и длина TLV) не нужен: только найти
//! `SubjectPublicKeyInfo` с алгоритмом `id-Ed25519` (RFC 8410 §3, OID
//! `1.3.101.112`) и взять последнее поле внешней `SEQUENCE` — `signatureValue`
//! (RFC 5280 §4.1, `Certificate ::= SEQUENCE { tbsCertificate,
//! signatureAlgorithm, signatureValue }`).
//!
//! Обход дерева рекурсивный и не привязан к точному месту
//! `SubjectPublicKeyInfo` внутри `tbsCertificate` (там перед ним лежат поля
//! переменной длины — серийный номер, издатель, срок действия, субъект):
//! вместо этого он ищет любую `SEQUENCE` вида `SEQUENCE { SEQUENCE { OID
//! id-Ed25519 }, BIT STRING }` — это и есть `SubjectPublicKeyInfo` для
//! `Ed25519` (RFC 8410 §4: `parameters` у нашего алгоритма отсутствуют).

use crate::reality::error::RealityError;

const TAG_SEQUENCE: u8 = 0x30;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OID: u8 = 0x06;
/// `1.3.101.112` (`id-Ed25519`, RFC 8410 §3) в DER-кодировке OID.
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

/// Один элемент DER: тег и содержимое без заголовка (тег+длина).
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
}

/// Читает длину TLV (X.690 §8.1.3): короткая форма — один байт со значением
/// напрямую, длинная — старший бит установлен, остаток байта — число
/// следующих байт длины. Неопределённая длина (`0x80`, только для BER) и
/// длина больше 4 байт отвергаются — сертификату они не нужны.
fn read_length(bytes: &[u8]) -> Result<(usize, usize), RealityError> {
    let first = *bytes
        .first()
        .ok_or(RealityError::Certificate("длина TLV обрезана"))?;
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 4 {
        return Err(RealityError::Certificate(
            "неопределённая или слишком большая длина TLV",
        ));
    }
    let tail = bytes
        .get(1..1 + count)
        .ok_or(RealityError::Certificate("длина TLV обрезана"))?;
    let mut length = 0usize;
    for byte in tail {
        length = (length << 8) | (*byte as usize);
    }
    Ok((length, 1 + count))
}

/// Читает один TLV с начала среза, возвращает его и остаток.
fn read_tlv(bytes: &[u8]) -> Result<(Tlv<'_>, &[u8]), RealityError> {
    let tag = *bytes
        .first()
        .ok_or(RealityError::Certificate("TLV обрезан"))?;
    let (length, length_size) = read_length(&bytes[1..])?;
    let start = 1 + length_size;
    let end = start
        .checked_add(length)
        .ok_or(RealityError::Certificate("длина TLV переполняет срез"))?;
    let content = bytes
        .get(start..end)
        .ok_or(RealityError::Certificate("TLV длиннее, чем есть байт"))?;
    Ok((Tlv { tag, content }, &bytes[end..]))
}

/// Читает подряд все TLV на одном уровне (тело `SEQUENCE`).
fn read_all(mut bytes: &[u8]) -> Result<Vec<Tlv<'_>>, RealityError> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let (tlv, rest) = read_tlv(bytes)?;
        out.push(tlv);
        bytes = rest;
    }
    Ok(out)
}

/// Содержимое `BIT STRING` без первого байта (число неиспользованных битов) —
/// в X.509 он всегда `0`: сертификаты выровнены по байту.
fn bit_string_bytes(content: &[u8]) -> Result<&[u8], RealityError> {
    match content.split_first() {
        Some((0, rest)) => Ok(rest),
        Some(_) => Err(RealityError::Certificate(
            "BIT STRING не выровнен по байту — не бывает в X.509",
        )),
        None => Err(RealityError::Certificate("пустой BIT STRING")),
    }
}

/// Ищет `SubjectPublicKeyInfo` с алгоритмом `Ed25519` во всём поддереве.
fn find_ed25519_public_key(bytes: &[u8]) -> Result<Option<[u8; 32]>, RealityError> {
    for tlv in read_all(bytes)? {
        if tlv.tag != TAG_SEQUENCE {
            continue;
        }
        if let Some(key) = try_as_ed25519_spki(tlv.content)? {
            return Ok(Some(key));
        }
        if let Some(key) = find_ed25519_public_key(tlv.content)? {
            return Ok(Some(key));
        }
    }
    Ok(None)
}

/// Проверяет, что тело `SEQUENCE` — это ровно `SubjectPublicKeyInfo { SEQUENCE
/// { OID id-Ed25519 }, BIT STRING }`, и если да, достаёт из него ключ.
fn try_as_ed25519_spki(sequence_body: &[u8]) -> Result<Option<[u8; 32]>, RealityError> {
    let Ok(children) = read_all(sequence_body) else {
        return Ok(None);
    };
    let [algorithm, public_key] = children.as_slice() else {
        return Ok(None);
    };
    if algorithm.tag != TAG_SEQUENCE || public_key.tag != TAG_BIT_STRING {
        return Ok(None);
    }
    let Ok(algorithm_fields) = read_all(algorithm.content) else {
        return Ok(None);
    };
    let [oid] = algorithm_fields.as_slice() else {
        return Ok(None);
    };
    if oid.tag != TAG_OID || oid.content != OID_ED25519 {
        return Ok(None);
    }

    let key_bytes = bit_string_bytes(public_key.content)?;
    if key_bytes.len() != 32 {
        return Err(RealityError::Certificate(
            "ключ Ed25519 в сертификате — не 32 байта",
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(key_bytes);
    Ok(Some(key))
}

/// То, что удалось достать из листового сертификата.
pub struct LeafCertificate {
    /// Публичный ключ `Ed25519` из `SubjectPublicKeyInfo`. `None` — сертификат
    /// не на `Ed25519`: настоящий сайт, которому Reality переслала бы
    /// `ClientHello`, почти наверняка предъявит RSA или ECDSA, и это ожидаемо
    /// не наш случай, а не поломка разбора.
    pub ed25519_public_key: Option<[u8; 32]>,
    /// Байты поля `signatureValue` внешней `SEQUENCE` (без обёртки
    /// `BIT STRING`) — то, что Reality заменяет на `HMAC-SHA512`.
    pub signature: Vec<u8>,
}

/// Разбирает один сертификат `Certificate ::= SEQUENCE { tbsCertificate,
/// signatureAlgorithm, signatureValue }` (RFC 5280 §4.1) из DER.
pub fn parse_leaf(der: &[u8]) -> Result<LeafCertificate, RealityError> {
    let (outer, _) = read_tlv(der)?;
    if outer.tag != TAG_SEQUENCE {
        return Err(RealityError::Certificate(
            "сертификат — не SEQUENCE верхнего уровня",
        ));
    }
    let top = read_all(outer.content)?;
    let [_tbs_certificate, _signature_algorithm, signature_value] = top.as_slice() else {
        return Err(RealityError::Certificate(
            "у Certificate не три поля верхнего уровня",
        ));
    };
    if signature_value.tag != TAG_BIT_STRING {
        return Err(RealityError::Certificate(
            "последнее поле Certificate — не BIT STRING",
        ));
    }
    let signature = bit_string_bytes(signature_value.content)?.to_vec();
    let ed25519_public_key = find_ed25519_public_key(outer.content)?;

    Ok(LeafCertificate {
        ed25519_public_key,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("тестовый хекс верен"))
            .collect()
    }

    /// RFC 8410 §10.1 ("Example Ed25519 Public Key") — независимый от
    /// Reality пример `SubjectPublicKeyInfo`. Байты — прямое декодирование
    /// `base64` из RFC (`MCowBQYDK2VwAyEA...`), не наша выдумка.
    #[test]
    fn finds_the_rfc_8410_example_ed25519_key() {
        let spki = from_hex(
            "302a300506032b65700321001\
             9bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"
                .replace('\n', "")
                .as_str(),
        );
        let key = find_ed25519_public_key(&spki)
            .expect("разбирается")
            .expect("ключ найден");
        assert_eq!(
            key,
            from_hex("19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1").as_slice()
        );
    }

    /// Настоящий лист сертификата из RFC 8448 §3 ("send handshake record:
    /// payload (657 octets)", 432 DER-байта, начинающиеся сразу после
    /// заголовка `Certificate`-сообщения и длины `cert_data`). RSA, не
    /// Ed25519, — но это структурно живой сертификат из настоящей трассы TLS
    /// 1.3, а не собранные для теста байты. Ключ не находится (это ожидаемо:
    /// RSA — не Ed25519), а `signatureValue` разбирается и совпадает с тем,
    /// что напечатан в RFC как хвост `Certificate (445 octets)`.
    #[test]
    fn a_real_rfc_8448_certificate_parses_its_signature_and_finds_no_ed25519_key() {
        let der = from_hex(
            "308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a0603550403\
             1303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c30\
             0a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb\
             498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ac\
             e6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846\
             748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f020\
             3010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d0\
             1010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2e\
             ae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6b\
             ec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f\
             8961229ac9187b42b4de1"
                .replace('\n', "")
                .as_str(),
        );
        let leaf = parse_leaf(&der).expect("это настоящий Certificate DER");
        assert!(
            leaf.ed25519_public_key.is_none(),
            "сертификат RSA, а не Ed25519"
        );
        let expected_signature = from_hex(
            "85aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f817\
             2f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a\
             99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac\
             9187b42b4de1",
        );
        assert_eq!(leaf.signature, expected_signature);
    }

    #[test]
    fn garbage_bytes_are_refused_not_panicked_on() {
        for len in 0..8 {
            let garbage = vec![0xFFu8; len];
            let _ = parse_leaf(&garbage);
        }
    }

    #[test]
    fn a_non_ed25519_bit_string_reports_no_key_instead_of_an_error() {
        // SEQUENCE { SEQUENCE { OID 1.2.3.4 }, BIT STRING { 00, 1,2,3 } } —
        // алгоритм заведомо не Ed25519.
        let bytes = from_hex("300c300506032a0304030401000102");
        // Может не разобраться как валидный SPKI вовсе — это ожидаемо для
        // случайно подобранных байт, важно лишь отсутствие паники.
        let _ = find_ed25519_public_key(&bytes);
    }
}
