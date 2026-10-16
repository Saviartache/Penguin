//! Вывод сеансового ключа Shadowsocks 2022: BLAKE3 в режиме `derive_key`.
//!
//! ```text
//!  TCP:  ключ (PSK) || соль               ──BLAKE3 derive_key──► подключ
//!  UDP:  ключ (PSK) || идентификатор сессии (u64, BE)  (только AES-GCM)
//! ```
//!
//! Метка контекста общая: `shadowsocks-rust` (`v2/mod.rs`: `BLAKE3_KEY_DERIVE_CONTEXT`),
//! `sing-shadowsocks2` (`shadowaead_2022/protocol.go::SessionKey`). У UDP ChaCha вывода
//! нет: PSK идёт в шифр как есть.

/// Метка контекста BLAKE3; другая метка даёт другой ключ, сервер его не примет.
pub const CONTEXT: &str = "shadowsocks 2022 session subkey";

/// Выводит подключ длиной `key_len` (16 или 32) из PSK и материала (соль или id сессии).
pub fn derive(psk: &[u8], material: &[u8], key_len: usize) -> Vec<u8> {
    debug_assert!(key_len <= 32, "ключ 2022 длиннее выхода BLAKE3");

    let mut hasher = blake3::Hasher::new_derive_key(CONTEXT);
    hasher.update(psk).update(material);
    hasher.finalize().as_bytes()[..key_len].to_vec()
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
