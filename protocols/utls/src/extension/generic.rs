//! Общие формы расширений: списки чисел, строк и пустое тело.

/// Список u16 с 16-битной длиной: `signature_algorithms`, `supported_groups`.
pub fn u16_list_u16_len(ext_type: u16, items: &[u16]) -> Vec<u8> {
    let inner_len = 2 * items.len();
    let mut out = Vec::with_capacity(6 + inner_len);
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&u16_len(2 + inner_len));
    out.extend_from_slice(&u16_len(inner_len));
    for item in items {
        out.extend_from_slice(&item.to_be_bytes());
    }
    out
}

/// Список u16 с однобайтной длиной: `supported_versions`, `compress_certificate`.
pub fn u16_list_u8_len(ext_type: u16, items: &[u16]) -> Vec<u8> {
    let inner_len = 2 * items.len();
    let mut out = Vec::with_capacity(5 + inner_len);
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&u16_len(1 + inner_len));
    out.push(inner_len as u8);
    for item in items {
        out.extend_from_slice(&item.to_be_bytes());
    }
    out
}

/// Список байт с однобайтной длиной: `ec_point_formats`,
/// `psk_key_exchange_modes`.
pub fn u8_list(ext_type: u16, items: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + items.len());
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&u16_len(1 + items.len()));
    out.push(items.len() as u8);
    out.extend_from_slice(items);
    out
}

/// Список строк с однобайтной длиной каждой: ALPN (16) и ALPS (`17513`, `17613`).
pub fn string_list(ext_type: u16, items: &[&[u8]]) -> Vec<u8> {
    let strings_len: usize = items.iter().map(|s| 1 + s.len()).sum();
    let mut out = Vec::with_capacity(6 + strings_len);
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&u16_len(2 + strings_len));
    out.extend_from_slice(&u16_len(strings_len));
    for item in items {
        out.push(item.len() as u8);
        out.extend_from_slice(item);
    }
    out
}

/// Расширение без тела: `extended_master_secret`, `sct`, `session_ticket`.
pub fn empty(ext_type: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

fn u16_len(len: usize) -> [u8; 2] {
    (len as u16).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_u16_list_carries_two_length_fields() {
        let bytes = u16_list_u16_len(13, &[0x0403, 0x0804]);
        assert_eq!(&bytes[0..2], &13u16.to_be_bytes());
        assert_eq!(&bytes[2..4], &6u16.to_be_bytes(), "заголовок расширения");
        assert_eq!(&bytes[4..6], &4u16.to_be_bytes(), "длина самого списка");
        assert_eq!(&bytes[6..], &[0x04, 0x03, 0x08, 0x04]);
    }

    #[test]
    fn a_u16_list_with_a_byte_length_uses_one_byte_for_the_count() {
        let bytes = u16_list_u8_len(43, &[0x0a0a, 0x0304, 0x0303]);
        assert_eq!(&bytes[0..2], &43u16.to_be_bytes());
        assert_eq!(&bytes[2..4], &7u16.to_be_bytes());
        assert_eq!(bytes[4], 6, "три записи по два байта");
        assert_eq!(&bytes[5..], &[0x0a, 0x0a, 0x03, 0x04, 0x03, 0x03]);
    }

    #[test]
    fn a_byte_list_is_flat() {
        let bytes = u8_list(11, &[0]);
        assert_eq!(bytes, vec![0, 11, 0, 2, 1, 0]);
    }

    #[test]
    fn a_string_list_prefixes_each_string_with_its_own_length() {
        let bytes = string_list(16, &[b"h2".as_slice(), b"http/1.1".as_slice()]);
        assert_eq!(&bytes[0..2], &16u16.to_be_bytes());
        // 1+2 (h2) + 1+8 (http/1.1) = 12, плюс два байта на общую длину.
        assert_eq!(&bytes[2..4], &14u16.to_be_bytes());
        assert_eq!(&bytes[4..6], &12u16.to_be_bytes());
        assert_eq!(&bytes[6..9], &[2, b'h', b'2']);
        assert_eq!(&bytes[9..], b"\x08http/1.1");
    }

    #[test]
    fn an_empty_extension_is_four_bytes() {
        assert_eq!(empty(23), vec![0, 23, 0, 0]);
    }
}
