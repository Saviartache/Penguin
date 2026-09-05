//! `key_share` (51) — RFC 8446 §4.2.8.
//!
//! Список пар «группа, публичное значение», каждая со своей длиной. Порядок
//! записей — это порядок предпочтения клиента: сервер обязан взять первую,
//! под которую у него есть ключ, и только если ни одна не подошла — просить
//! `HelloRetryRequest`. У Chrome и Safari запись одна настоящая (`X25519`) и
//! одна пустышка GREASE; у Firefox — две настоящие (`X25519` и `P-256`), и
//! сервер, которому нужен именно `P-256`, получает его без второго круга.

/// Одна запись `key_share`: группа и байты публичного значения (32 байта для
/// `X25519`, 65 — несжатая точка для `P-256`: `0x04`, потом X и Y по 32).
pub struct Entry<'a> {
    /// Код группы: например, `29` (`X25519`) или GREASE-плейсхолдер.
    pub group: u16,
    /// Публичное значение этой группы.
    pub data: &'a [u8],
}

const EXTENSION_TYPE: u16 = 51;

/// Кодирует `key_share` из списка записей в заданном порядке.
pub fn encode(entries: &[Entry<'_>]) -> Vec<u8> {
    let entries_len: usize = entries.iter().map(|e| 4 + e.data.len()).sum();
    let mut out = Vec::with_capacity(6 + entries_len);
    out.extend_from_slice(&EXTENSION_TYPE.to_be_bytes());
    out.extend_from_slice(&((2 + entries_len) as u16).to_be_bytes());
    out.extend_from_slice(&(entries_len as u16).to_be_bytes());
    for entry in entries {
        out.extend_from_slice(&entry.group.to_be_bytes());
        out.extend_from_slice(&(entry.data.len() as u16).to_be_bytes());
        out.extend_from_slice(entry.data);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_entries_are_laid_out_one_after_another() {
        let bytes = encode(&[
            Entry {
                group: 0x0a0a,
                data: &[0],
            },
            Entry {
                group: 29,
                data: &[0xAB; 32],
            },
        ]);
        assert_eq!(&bytes[0..2], &51u16.to_be_bytes());
        // (4+1) + (4+32) = 41, плюс два байта на общую длину списка.
        assert_eq!(&bytes[2..4], &43u16.to_be_bytes());
        assert_eq!(&bytes[4..6], &41u16.to_be_bytes());
        assert_eq!(&bytes[6..8], &0x0a0au16.to_be_bytes());
        assert_eq!(&bytes[8..10], &1u16.to_be_bytes());
        assert_eq!(bytes[10], 0);
        assert_eq!(&bytes[11..13], &29u16.to_be_bytes());
        assert_eq!(&bytes[13..15], &32u16.to_be_bytes());
        assert_eq!(&bytes[15..], &[0xAB; 32]);
    }
}
