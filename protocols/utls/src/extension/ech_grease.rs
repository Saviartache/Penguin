//! `encrypted_client_hello` (`0xfe0d`) — GREASE-вариант, draft-ietf-tls-esni.
//!
//! Настоящий ECH прячет второй, внутренний `ClientHello` внутри
//! HPKE-шифротекста, и без ключа сервера собрать его нельзя — этим и
//! занимается Reality не по этой части спецификации, а по своей. GREASE-же
//! версия не шифрует ничего: сервер, который ECH не поддерживает, обязан
//! молча пропустить незнакомое расширение, а сервер, который поддерживает,
//! должен уметь отличить настоящий ECH от учебной тревоги. Random-байты
//! правильной длины и формы для этого достаточны — расшифровывать их никто
//! не обязан и не будет.
//!
//! Форма взята из `GREASEEncryptedClientHelloExtension` (uTLS, `u_ech.go`).
//! Умолчание для Chrome (`BoringGREASEECH()`) называет только один вариант
//! AEAD; у Firefox их два, и он выбирает между ними на каждое соединение —
//! поэтому список кандидатов AEAD и список длин полезной нагрузки здесь
//! параметры, а не константы: у каждого отпечатка свой набор (см.
//! соответствующий модуль в `crate::fingerprint`).

use rand::RngCore;

const EXTENSION_TYPE: u16 = 0xfe0d;

/// Тип «внешнего» `ClientHello` в поле `ClientHelloType` — единственное
/// значение, которое отправляет клиент: внутренний `ClientHello` в GREASE не
/// существует вовсе.
const OUTER_CLIENT_HELLO: u8 = 0;

/// HPKE KDF: `HKDF-SHA256`. Единственный, которым пользуется GREASE и у
/// Chrome, и у Firefox — разница между ними только в AEAD.
const HKDF_SHA256: u16 = 0x0001;

/// HPKE AEAD `AES-128-GCM`. Кандидат GREASE и у Chrome, и у Firefox.
pub const AEAD_AES_128_GCM: u16 = 0x0001;

/// HPKE AEAD `ChaCha20-Poly1305`. Второй кандидат GREASE у Firefox — у
/// Chrome (`BoringGREASEECH()`) его нет.
pub const AEAD_CHACHA20_POLY1305: u16 = 0x0003;

/// Длина тега — 16 байт у обоих AEAD выше, так что она не зависит от того,
/// какой из кандидатов выпал случайно.
const AEAD_TAG_LEN: usize = 16;

/// Длина инкапсулированного ключа `DHKEM(X25519, HKDF-SHA256)` — публичный
/// ключ X25519, 32 байта. Это тот KEM, который GREASE не называет явно, но
/// использует по умолчанию что у Chrome, что у Firefox.
const ENCAPSULATED_KEY_LEN: usize = 32;

/// Кодирует GREASE ECH.
///
/// `candidate_aeads` — из чего выбирается AEAD (см. константы выше);
/// `candidate_payload_lens` — длины открытого текста, из которых выбирается
/// одна случайно. И то, и другое утекает на провод только длиной и видом
/// расширения — расшифровывать его не должен и не будет ни один сервер, —
/// но точность здесь дёшева, раз оба списка уже выписаны в исходнике uTLS.
pub fn encode(
    rng: &mut impl RngCore,
    candidate_aeads: &[u16],
    candidate_payload_lens: &[u16],
) -> Vec<u8> {
    let aead = candidate_aeads[(rng.next_u32() as usize) % candidate_aeads.len()];
    let config_id = (rng.next_u32() & 0xff) as u8;

    let mut encapsulated_key = [0u8; ENCAPSULATED_KEY_LEN];
    rng.fill_bytes(&mut encapsulated_key);

    let index = (rng.next_u32() as usize) % candidate_payload_lens.len();
    let payload_len = usize::from(candidate_payload_lens[index]) + AEAD_TAG_LEN;
    let mut payload = vec![0u8; payload_len];
    rng.fill_bytes(&mut payload);

    let body_len = 1 + 4 + 1 + 2 + ENCAPSULATED_KEY_LEN + 2 + payload_len;
    let mut out = Vec::with_capacity(4 + body_len);
    out.extend_from_slice(&EXTENSION_TYPE.to_be_bytes());
    out.extend_from_slice(&(body_len as u16).to_be_bytes());
    out.push(OUTER_CLIENT_HELLO);
    out.extend_from_slice(&HKDF_SHA256.to_be_bytes());
    out.extend_from_slice(&aead.to_be_bytes());
    out.push(config_id);
    out.extend_from_slice(&(ENCAPSULATED_KEY_LEN as u16).to_be_bytes());
    out.extend_from_slice(&encapsulated_key);
    out.extend_from_slice(&(payload_len as u16).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shape_matches_a_real_hpke_grease_record() {
        let mut rng = rand::rngs::mock::StepRng::new(1, 1);
        let bytes = encode(&mut rng, &[AEAD_AES_128_GCM], &[128, 160, 192, 224]);

        assert_eq!(&bytes[0..2], &0xfe0du16.to_be_bytes());
        assert_eq!(bytes[4], OUTER_CLIENT_HELLO);
        assert_eq!(&bytes[5..7], &HKDF_SHA256.to_be_bytes());
        assert_eq!(&bytes[7..9], &AEAD_AES_128_GCM.to_be_bytes());
        assert_eq!(&bytes[10..12], &32u16.to_be_bytes(), "длина enc: X25519");
        let payload_len_field = u16::from_be_bytes([bytes[44], bytes[45]]) as usize;
        assert_eq!(bytes.len(), 46 + payload_len_field);
        // Одна из четырёх длин плюс тег AES-128-GCM.
        assert!([144, 176, 208, 240].contains(&payload_len_field));
    }

    #[test]
    fn a_second_aead_candidate_can_be_picked_too() {
        // У Firefox два кандидата AEAD; убеждаемся, что оба реально доходят
        // до провода, а не только первый в списке.
        let mut seen = std::collections::HashSet::new();
        for seed in 0..32u64 {
            let mut rng = rand::rngs::mock::StepRng::new(seed, 1);
            let bytes = encode(
                &mut rng,
                &[AEAD_AES_128_GCM, AEAD_CHACHA20_POLY1305],
                &[223],
            );
            seen.insert(u16::from_be_bytes([bytes[7], bytes[8]]));
        }
        assert_eq!(seen.len(), 2, "оба кандидата AEAD должны встретиться");
    }

    #[test]
    fn two_calls_do_not_repeat_the_same_random_bytes() {
        // Не строгая гарантия, а сигнал: если GREASE ECH станет повторяться
        // байт в байт между `ClientHello`, по нему саму GREASE и опознают.
        let mut rng = rand::rngs::mock::StepRng::new(7, 11);
        let first = encode(&mut rng, &[AEAD_AES_128_GCM], &[128]);
        let second = encode(&mut rng, &[AEAD_AES_128_GCM], &[128]);
        assert_ne!(first, second);
    }
}
