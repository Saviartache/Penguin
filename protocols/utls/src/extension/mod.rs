//! Кодировщики отдельных расширений `ClientHello`.
//!
//! Каждая функция отдаёт байты одного расширения (заголовок и тело); порядок
//! задаёт отпечаток ([`crate::fingerprint`]).

pub mod ech_grease;
pub mod fixed;
pub mod generic;
pub mod key_share;
pub mod padding;
pub mod sni;

/// Псевдорасширение GREASE; тело пустое у первого и `[0]` у второго (uTLS `UtlsGREASEExtension`).
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
