//! Кирпичи представлений QPACK: целое с префиксом и строка (RFC 9204, §4.1;
//! формат — RFC 7541, §5.1–5.2).
//!

use super::QpackError;
use super::huffman;

/// Дописывает целое с `prefix`-битным префиксом; `flags` — старшие биты
/// первого байта.
pub fn encode_int(value: u64, prefix: u8, flags: u8, out: &mut Vec<u8>) {
    let max = (1u64 << prefix) - 1;
    if value < max {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max as u8);
    let mut rest = value - max;
    while rest >= 0x80 {
        out.push((rest as u8 & 0x7f) | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

/// Читает целое с `prefix`-битным префиксом. Возвращает значение и число
/// прочитанных байт.
pub fn decode_int(src: &[u8], prefix: u8) -> Result<(u64, usize), QpackError> {
    let max = (1u64 << prefix) - 1;
    let first = *src.first().ok_or(QpackError::Truncated)?;
    let value = u64::from(first) & max;
    if value < max {
        return Ok((value, 1));
    }

    let mut value = value;
    let mut shift = 0u32;
    for (index, &byte) in src.iter().enumerate().skip(1) {
        // QPACK обязан понимать 62 бита и не больше (RFC 9204, §4.1.1).
        if shift > 62 {
            return Err(QpackError::Integer);
        }
        value = u64::from(byte & 0x7f)
            .checked_mul(1 << shift)
            .and_then(|part| value.checked_add(part))
            .ok_or(QpackError::Integer)?;
        if value > crate::varint::MAX_VALUE {
            return Err(QpackError::Integer);
        }
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
        shift += 7;
    }
    Err(QpackError::Truncated)
}

/// Дописывает строку с `prefix`-битным префиксом длины; бит Хаффмана стоит
/// сразу над префиксом. Хаффман — когда он короче, как делают все.
pub fn encode_str(src: &[u8], prefix: u8, flags: u8, out: &mut Vec<u8>) {
    let huffman_len = huffman::encoded_len(src);
    if huffman_len < src.len() {
        encode_int(huffman_len as u64, prefix, flags | (1 << prefix), out);
        huffman::encode(src, out);
    } else {
        encode_int(src.len() as u64, prefix, flags, out);
        out.extend_from_slice(src);
    }
}

/// Читает строку с `prefix`-битным префиксом длины. Возвращает строку и
/// число прочитанных байт.
pub fn decode_str(src: &[u8], prefix: u8) -> Result<(Vec<u8>, usize), QpackError> {
    let first = *src.first().ok_or(QpackError::Truncated)?;
    let huffman = first & (1 << prefix) != 0;
    let (len, head) = decode_int(src, prefix)?;
    let end = usize::try_from(len)
        .ok()
        .and_then(|len| head.checked_add(len))
        .ok_or(QpackError::Truncated)?;
    let raw = src.get(head..end).ok_or(QpackError::Truncated)?;
    let text = if huffman {
        huffman::decode(raw)?
    } else {
        raw.to_vec()
    };
    Ok((text, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rfc_7541_integer_examples() {
        // RFC 7541, приложения C.1.1–C.1.3.
        let cases: &[(u64, u8, &[u8])] = &[
            (10, 5, &[0x0a]),
            (1337, 5, &[0x1f, 0x9a, 0x0a]),
            (42, 8, &[0x2a]),
        ];
        for &(value, prefix, wire) in cases {
            let mut out = Vec::new();
            encode_int(value, prefix, 0, &mut out);
            assert_eq!(out, wire, "кодирование {value}");
            assert_eq!(decode_int(wire, prefix), Ok((value, wire.len())));
        }
    }

    #[test]
    fn flags_above_the_prefix_are_kept_and_ignored() {
        let mut out = Vec::new();
        encode_int(3, 6, 0xc0, &mut out);
        assert_eq!(out, [0xc3]);
        assert_eq!(decode_int(&out, 6), Ok((3, 1)));
    }

    #[test]
    fn an_integer_past_62_bits_is_refused() {
        let mut wire = vec![0xff];
        wire.extend([0xff; 9]);
        wire.push(0x01);
        assert_eq!(decode_int(&wire, 8), Err(QpackError::Integer));
    }

    #[test]
    fn a_truncated_integer_is_reported() {
        assert_eq!(decode_int(&[0x1f, 0x9a], 5), Err(QpackError::Truncated));
        assert_eq!(decode_int(&[], 5), Err(QpackError::Truncated));
    }

    #[test]
    fn strings_pick_huffman_only_when_shorter() {
        let mut out = Vec::new();
        encode_str(b"www.example.com", 7, 0, &mut out);
        // RFC 7541, C.4.1: `8c` — Хаффман, 12 байт.
        assert_eq!(out[0], 0x8c);
        assert_eq!(decode_str(&out, 7), Ok((b"www.example.com".to_vec(), 13)));

        // Хаффман у редких байтов длиннее исходника — уходит как есть.
        let raw = [0x00, 0x01];
        let mut out = Vec::new();
        encode_str(&raw, 7, 0, &mut out);
        assert_eq!(out, [0x02, 0x00, 0x01]);
    }

    #[test]
    fn a_string_longer_than_the_block_is_truncated() {
        assert_eq!(decode_str(&[0x05, b'a'], 7), Err(QpackError::Truncated));
    }
}
