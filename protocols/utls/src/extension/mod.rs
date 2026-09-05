//! Кодировщики отдельных расширений `ClientHello`.
//!
//! Каждая функция здесь ничего не знает про отпечаток целиком: она берёт
//! готовые значения (список кривых, имя хоста, публичный ключ) и отдаёт уже
//! готовые байты одного расширения — заголовок и тело вместе. Собирает их в
//! порядок, который называется отпечатком браузера, модуль
//! [`crate::fingerprint`].
//!
//! ```text
//!  generic      формы, общие для нескольких расширений: список чисел,
//!               список строк, пустое тело
//!  sni          server_name (0)
//!  fixed        расширения с одним и тем же телом всегда: status_request,
//!               renegotiation_info, record_size_limit
//!  key_share    key_share (51): список пар «группа, публичный ключ»
//!  padding      padding (21) по правилу BoringSSL
//!  ech_grease   encrypted_client_hello (0xfe0d), GREASE-вариант
//! ```

pub mod ech_grease;
pub mod fixed;
pub mod generic;
pub mod key_share;
pub mod padding;
pub mod sni;

/// Кодирует псевдорасширение GREASE: код `value` (уже одно из шестнадцати
/// значений вида `0x?A?A`) и произвольное тело.
///
/// Тело различает первое и второе псевдорасширение в отпечатках Chrome и
/// Safari: у первого (перед SNI) оно пустое, у второго (перед `padding`) —
/// один нулевой байт. Разница воспроизведена по `UtlsGREASEExtension.Body` в
/// uTLS: комментарий там же говорит, что это устоявшееся поведение
/// BoringSSL, а не решение самого uTLS.
pub fn grease_placeholder(value: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&value.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grease_extension_carries_its_own_value_as_the_type() {
        let bytes = grease_placeholder(0x3a3a, &[]);
        assert_eq!(bytes, vec![0x3a, 0x3a, 0, 0]);
    }

    #[test]
    fn the_second_grease_extension_carries_one_zero_byte() {
        let bytes = grease_placeholder(0x3a3a, &[0]);
        assert_eq!(bytes, vec![0x3a, 0x3a, 0, 1, 0]);
    }
}
