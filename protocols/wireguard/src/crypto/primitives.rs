//! Кирпичи рукопожатия: `HASH`, `HMAC`, KDF в один-два-три выхода, `MAC`,
//! `AEAD` — ровно те примитивы, которыми оперирует псевдокод спецификации
//! (`wireguard.com/protocol/`, разделы «First/Second Message»).
//!
//! Важное различие, о которое легко споткнуться: `HMAC()` из псевдокода — это
//! **обычный HMAC** (RFC 2104) над BLAKE2s-256, а `MAC()` (для `mac1`/`mac2`)
//! — это **керированный BLAKE2s**, то есть встроенный в сам алгоритм режим
//! ключа, а не HMAC. Это два разных примитива с одинаковым словом «MAC» в
//! названии; перепутать их — значит посчитать `mac1` так, что ни один сервер
//! его не примет, и это будет выглядеть не ошибкой, а тишиной.
//!
//! Источник обоих: `device/noise-helpers.go` (`HMAC1`/`HMAC2`, через
//! `blake2s.New256`) и `device/cookie.go` (`WGLabelMAC1`,
//! `blake2s.New128(key)`) в `wireguard-go`; формулы `KDF1`/`KDF2`/`KDF3` там
//! же, в `HMAC1`/`HMAC2`/`KDF1`/`KDF2`/`KDF3` (`device/noise-helpers.go`).
//!
//! # Почему `HMAC()` здесь не крейт `hmac`
//!
//! Генерический `hmac` из RustCrypto собирается только над хэшами с
//! «нетерпеливой» (`Eager`) буферизацией блока. BLAKE2 буферизует «лениво»
//! (`Lazy`) — ему нужно знать, последний это блок или нет, до того, как его
//! сжать, — и это не подгонка реализации, а свойство самого алгоритма сжатия
//! BLAKE2. Поэтому `Hmac<Blake2s256>` не собирается вовсе: `CoreWrapper`
//! вокруг `Blake2sVarCore` не реализует типаж, который требует `hmac`
//! (`BufferKindUser<BufferKind = Eager>`). Это не то же самое, что не найти
//! подходящую версию зависимости, — конструкция несовместима на уровне
//! типажей при любой версии обоих крейтов. HMAC-BLAKE2s ниже собран вручную
//! по RFC 2104 поверх `Blake2s256::update`/`finalize`, которые «ленивости»
//! не боятся: `Digest` сам решает, когда сообщение закончилось, только на
//! вызове `finalize`.

use blake2::Blake2s256;
use blake2::digest::Digest;
use blake2::digest::consts::U16;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as AeadKeyInit, Nonce};

use crate::crypto::constants::{AEAD_TAG_LEN, KEY_LEN, MAC_LEN};
use crate::error::{WireguardError, WireguardResult};

/// Размер блока BLAKE2s в байтах — нужен для ручного HMAC.
const BLAKE2S_BLOCK_LEN: usize = 64;

/// `HASH(data) = BLAKE2s-256(data)`.
pub fn hash(parts: &[&[u8]]) -> [u8; KEY_LEN] {
    let mut hasher = Blake2s256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// `HMAC(key, input)` — обычный HMAC-BLAKE2s-256 (RFC 2104), а не
/// керированный BLAKE2s. Собран вручную — см. документ модуля.
fn hmac_blake2s(key: &[u8], parts: &[&[u8]]) -> [u8; KEY_LEN] {
    // Ключ длиннее блока хэшируется до длины блока; короче — дополняется
    // нулями. Оба случая здесь не встречаются (ключи этого протокола — 32
    // байта, блок BLAKE2s — 64), но обычное поведение HMAC от этого не
    // меняется.
    let mut key_block = [0u8; BLAKE2S_BLOCK_LEN];
    if key.len() > BLAKE2S_BLOCK_LEN {
        key_block[..KEY_LEN].copy_from_slice(&hash(&[key]));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLAKE2S_BLOCK_LEN];
    let mut opad = [0x5cu8; BLAKE2S_BLOCK_LEN];
    for i in 0..BLAKE2S_BLOCK_LEN {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Blake2s256::new();
    inner.update(ipad);
    for part in parts {
        inner.update(part);
    }
    let inner_digest = inner.finalize();

    let mut outer = Blake2s256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

/// `Kdf1`: один выход. Используется там, где второй `HMAC`-раунд не нужен
/// (раскладка `mixKey` в `wireguard-go`: `KDF1(dst, chainKey, dh)`).
pub fn kdf1(chaining_key: &[u8; KEY_LEN], input: &[u8]) -> [u8; KEY_LEN] {
    let temp = hmac_blake2s(chaining_key, &[input]);
    hmac_blake2s(&temp, &[&[0x1]])
}

/// `Kdf2`: два выхода — новый `chaining_key` и производный ключ AEAD.
///
/// Источник: `KDF2` в `device/noise-helpers.go` — `prk = HMAC(key, input)`,
/// `t0 = HMAC(prk, 0x1)`, `t1 = HMAC(prk, t0 || 0x2)`.
pub fn kdf2(chaining_key: &[u8; KEY_LEN], input: &[u8]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let temp = hmac_blake2s(chaining_key, &[input]);
    let ck = hmac_blake2s(&temp, &[&[0x1]]);
    let key = hmac_blake2s(&temp, &[&ck, &[0x2]]);
    (ck, key)
}

/// `Kdf3`: три выхода — используется только при смешивании предварительного
/// ключа во втором сообщении.
///
/// Источник: `KDF3` в `device/noise-helpers.go` — тот же `prk`, что и в
/// `KDF2`, плюс третий раунд: `t2 = HMAC(prk, t1 || 0x3)`.
pub fn kdf3(
    chaining_key: &[u8; KEY_LEN],
    input: &[u8],
) -> ([u8; KEY_LEN], [u8; KEY_LEN], [u8; KEY_LEN]) {
    let temp = hmac_blake2s(chaining_key, &[input]);
    let ck = hmac_blake2s(&temp, &[&[0x1]]);
    let tau = hmac_blake2s(&temp, &[&ck, &[0x2]]);
    let key = hmac_blake2s(&temp, &[&tau, &[0x3]]);
    (ck, tau, key)
}

/// `MAC(key, data)` для `mac1`/`mac2` — керированный BLAKE2s с шестнадцатью
/// байтами выхода. **Не** HMAC: у BLAKE2 ключ участвует в самом алгоритме
/// сжатия, а не оборачивает хэш снаружи, как в HMAC.
///
/// Вызовы ниже — через полный путь типажа (`<Type as Trait>::method`), а не
/// через импорт типажей `KeyInit`/`Mac` в область видимости: оба объявляют
/// `new_from_slice` (`Mac: KeyInit`, но переобъявляет её же для читаемости
/// документации), и одновременный импорт обоих даёт неоднозначность на
/// сборке, а не во время выполнения.
pub fn mac(key: &[u8], data: &[u8]) -> [u8; MAC_LEN] {
    type Blake2sMac128 = blake2::Blake2sMac<U16>;

    // Ключ здесь всегда есть (либо хэш метки со статическим ключом, либо
    // полученная от сервера cookie) и не длиннее 32 байт — предела BLAKE2s;
    // `expect` оправдан тем же, чем и выше: это свойство алгоритма, а не
    // ввод с провода.
    #[allow(clippy::expect_used)]
    let mut hasher = <Blake2sMac128 as blake2::digest::KeyInit>::new_from_slice(key)
        .expect("ключ MAC не длиннее предела BLAKE2s");
    blake2::digest::Update::update(&mut hasher, data);
    blake2::digest::Mac::finalize(hasher).into_bytes().into()
}

/// `AEAD(key, counter, plaintext, auth_text)`: ChaCha20-Poly1305 с нонсом,
/// собранным из счётчика (четыре нулевых байта, затем счётчик как u64 little
/// endian — так и в рукопожатии со счётчиком 0, и в пакетах данных со своим).
pub fn aead_seal(key: &[u8; KEY_LEN], counter: u64, plaintext: &[u8], auth_text: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = nonce_from_counter(counter);
    let payload = chacha20poly1305::aead::Payload {
        msg: plaintext,
        aad: auth_text,
    };
    // Ключ и нонс здесь всегда верной длины (типы `Key`/`Nonce` из того же
    // крейта их гарантируют) — шифрование с ними отказать не может.
    #[allow(clippy::expect_used)]
    cipher
        .encrypt(&nonce, payload)
        .expect("шифрование с готовым ключом и нонсом не отказывает")
}

/// Обратное к [`aead_seal`]. Ошибка здесь — это либо чужой ключ, либо
/// испорченный на проводе пакет; отличить одно от другого по самому факту
/// отказа AEAD нельзя, и не нужно: оба случая ведут себя одинаково — пакет
/// отбрасывается.
pub fn aead_open(
    key: &[u8; KEY_LEN],
    counter: u64,
    ciphertext: &[u8],
    auth_text: &[u8],
) -> WireguardResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = nonce_from_counter(counter);
    let payload = chacha20poly1305::aead::Payload {
        msg: ciphertext,
        aad: auth_text,
    };
    cipher
        .decrypt(&nonce, payload)
        .map_err(|_| WireguardError::Malformed("метка подлинности не сошлась".into()))
}

/// Длина шифротекста AEAD для открытого текста данной длины — плюс метка.
pub const fn sealed_len(plaintext_len: usize) -> usize {
    plaintext_len + AEAD_TAG_LEN
}

fn nonce_from_counter(counter: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    *Nonce::from_slice(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::constants::{CONSTRUCTION, IDENTIFIER};

    /// BLAKE2s-256 пустой строки — тестовый вектор из RFC 7693, приложение E
    /// (официальный тестовый набор BLAKE2), сверен ещё и заново через
    /// `openssl dgst -blake2s256` (OpenSSL 3.5) на пустом вводе — независимо
    /// от остальной реализации. Черновик этого файла нёс тот же вектор без
    /// последнего шестнадцатеричного разряда (63 символа вместо 64, `...eef`
    /// вместо `...eef9`) — `hex32` падал на разборе, а не тихо принимал
    /// усечённое значение.
    #[test]
    fn blake2s_matches_the_rfc_7693_test_vector() {
        let digest = hash(&[b""]);
        assert_eq!(
            digest,
            hex32("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
        );
    }

    /// `InitialChainKey` и `InitialHash` сверены двумя независимыми путями:
    /// байты `boringtun` (`boringtun/src/noise/handshake.rs`,
    /// `INITIAL_CHAIN_KEY`/`INITIAL_CHAIN_HASH`) и отдельно — BLAKE2s-256 из
    /// OpenSSL 3.5 (`openssl` в среде разработки, алгоритм `blake2s256`),
    /// посчитанный над теми же строками вне этого крейта и вне Rust вообще.
    /// Оба совпали с числами ниже; это не прогон собственной формулы туда-
    /// обратно.
    #[test]
    fn the_initial_chaining_key_and_hash_match_an_independent_implementation() {
        let initial_chain_key = hash(&[CONSTRUCTION]);
        assert_eq!(
            initial_chain_key,
            [
                96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235,
                66, 6, 248, 114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
            ]
        );

        let initial_hash = hash(&[&initial_chain_key, IDENTIFIER]);
        assert_eq!(
            initial_hash,
            [
                34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108,
                102, 34, 147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
            ]
        );
    }

    #[test]
    fn aead_round_trips() {
        let key = [7u8; KEY_LEN];
        let sealed = aead_seal(&key, 5, b"hello", b"aad");
        assert_eq!(sealed.len(), sealed_len(5));
        let opened = aead_open(&key, 5, &sealed, b"aad").expect("расшифровывается");
        assert_eq!(opened, b"hello");
    }

    #[test]
    fn aead_rejects_the_wrong_counter() {
        // Тот же ключ, но нонс — часть договора: другой счётчик даёт другой
        // нонс, и метка подлинности перестаёт сходиться.
        let key = [7u8; KEY_LEN];
        let sealed = aead_seal(&key, 5, b"hello", b"aad");
        assert!(aead_open(&key, 6, &sealed, b"aad").is_err());
    }

    #[test]
    fn aead_rejects_tampered_auth_text() {
        let key = [7u8; KEY_LEN];
        let sealed = aead_seal(&key, 0, b"hello", b"aad-1");
        assert!(aead_open(&key, 0, &sealed, b"aad-2").is_err());
    }

    #[test]
    fn kdf2_outputs_differ_from_each_other() {
        let ck = [1u8; KEY_LEN];
        let (a, b) = kdf2(&ck, b"input");
        assert_ne!(a, b);
    }

    #[test]
    fn kdf3_first_two_outputs_match_kdf2() {
        // `Kdf3` — это `Kdf2` с одним дополнительным раундом; первые два
        // выхода обязаны совпасть, иначе где-то перепутан порядок аргументов
        // в HMAC-раундах.
        let ck = [1u8; KEY_LEN];
        let (ck2, key2) = kdf2(&ck, b"input");
        let (ck3, tau3, _key3) = kdf3(&ck, b"input");
        assert_eq!(ck2, ck3);
        assert_eq!(key2, tau3);
    }

    #[test]
    fn kdf1_matches_the_first_two_rounds_of_kdf2() {
        // `Kdf1` — первый раунд `HMAC1`/`HMAC1` без последующего смешивания
        // `ck'`: значение обязано совпасть со вторым выходом `mixKey`,
        // применённым к тому же ключу и входу, что и `Kdf1` использует внутри
        // себя первым раундом.
        let ck = [1u8; KEY_LEN];
        let (ck2, _key2) = kdf2(&ck, b"input");
        assert_eq!(kdf1(&ck, b"input"), ck2);
    }

    #[test]
    fn mac_depends_on_the_key_not_only_the_data() {
        let data = b"mac1 covers everything before it";
        let mac_a = mac(&[1u8; 32], data);
        let mac_b = mac(&[2u8; 32], data);
        assert_ne!(mac_a, mac_b);
    }

    /// Разбирает шестнадцатеричную запись в массив байт фиксированной длины.
    fn hex32(text: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("тест содержит hex");
        }
        out
    }
}
