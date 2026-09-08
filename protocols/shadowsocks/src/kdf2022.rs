//! Вывод сеансового ключа Shadowsocks 2022: BLAKE3 в режиме `derive_key`.
//!
//! ```text
//!  TCP:  ключ (PSK) || соль               ──BLAKE3 derive_key──► подключ
//!  UDP:  ключ (PSK) || идентификатор сессии (u64, BE)  (только AES-GCM)
//! ```
//!
//! Метка контекста одна и та же в обоих случаях — так делает и
//! `shadowsocks-rust` (`shadowsocks-crypto`, `src/v2/mod.rs`:
//! `BLAKE3_KEY_DERIVE_CONTEXT`, используется и в `v2/tcp/mod.rs`, и в
//! `v2/udp/aes_gcm.rs`), и независимо `sing-shadowsocks2`
//! (`shadowaead_2022/protocol.go::SessionKey`, дословно та же строка).
//!
//! У ChaCha20-Poly1305 в UDP этой функции нет вовсе: там PSK идёт в шифр как
//! есть, без вывода (`crate::udp2022::cipher`), и это тоже видно по обоим
//! источникам — `v2/udp/chacha20_poly1305.rs` получает ключ параметром, не
//! трогая соль; `shadowaead_2022/method.go` строит `udpCipher` из
//! `pskList[0]` один раз при создании метода, до всякой сессии.

/// Метка контекста BLAKE3. Часть договора с сервером: другая метка — другой
/// ключ, и сервер такой подключ не примет.
pub const CONTEXT: &str = "shadowsocks 2022 session subkey";

/// Выводит подключ нужной длины из PSK и материала (соли или идентификатора
/// сессии).
///
/// `key_len` — 16 или 32 (см. [`crate::method::Method2022::key_len`]);
/// `blake3::derive_key` выдаёт 32 байта, длины хватает всегда.
pub fn derive(psk: &[u8], material: &[u8], key_len: usize) -> Vec<u8> {
    debug_assert!(key_len <= 32, "ключ 2022 длиннее выхода BLAKE3");

    let mut input = Vec::with_capacity(psk.len() + material.len());
    input.extend_from_slice(psk);
    input.extend_from_slice(material);

    blake3::derive_key(CONTEXT, &input)[..key_len].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Шестнадцатеричная запись — только для сверки с чужими значениями.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn blake3_derive_key_matches_the_official_test_vector() {
        // Вектор из официального набора BLAKE3-team/BLAKE3
        // (`test_vectors/test_vectors.json`, случай с пустым материалом):
        // не про Shadowsocks, а про саму функцию `derive_key`, которую
        // вызывает `derive` этого файла. Метку "shadowsocks 2022 session
        // subkey" им не проверить — векторного пакета от настоящего сервера
        // 2022 неоткуда взять (см. документ крейта), и это единственная
        // внешняя проверка, какая здесь возможна.
        let context = "BLAKE3 2019-12-27 16:29:52 test vectors context";
        let output = blake3::derive_key(context, b"");
        assert_eq!(
            hex(&output),
            "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"
        );
    }

    #[test]
    fn the_context_is_the_literal_string_the_protocol_names() {
        assert_eq!(CONTEXT, "shadowsocks 2022 session subkey");
    }

    #[test]
    fn the_key_changes_with_the_material() {
        let psk = [7u8; 32];
        let first = derive(&psk, &[1u8; 32], 32);
        let second = derive(&psk, &[2u8; 32], 32);
        assert_ne!(first, second);
    }

    #[test]
    fn the_same_material_gives_the_same_key() {
        let psk = [7u8; 16];
        let material = [9u8; 16];
        assert_eq!(derive(&psk, &material, 16), derive(&psk, &material, 16));
    }

    #[test]
    fn a_shorter_key_is_a_prefix_of_the_longer_one() {
        // Обе длины выводятся из одного и того же выхода BLAKE3, просто
        // обрезанного: если это не так, где-то потерялась синхронизация.
        let psk = [3u8; 32];
        let material = [4u8; 32];
        let short = derive(&psk, &material, 16);
        let long = derive(&psk, &material, 32);
        assert_eq!(&long[..16], &short[..]);
    }
}
