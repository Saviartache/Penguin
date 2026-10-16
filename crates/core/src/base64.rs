//! Base64 без зависимостей; нужен и протоколам (ключи), и окну (ссылки `vmess://`, `ss://`).
//!
//! Разбор мягкий: принимает оба алфавита (`+/` и `-_`), необязательное `=` и
//! ненулевые лишние биты в последнем символе. Посторонний символ, `=` посреди
//! строки и оборванный символ — ошибка.

use crate::error::{CoreError, CoreResult};

/// Обычный алфавит (RFC 4648, §4).
const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Алфавит для URL (RFC 4648, §5): вместо `+/` — `-_`.
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Кодирует байты обычным алфавитом с дополнением.
pub fn encode(bytes: &[u8]) -> String {
    encode_with(bytes, STANDARD, true)
}

/// Кодирует байты алфавитом для URL, без дополнения.
pub fn encode_url(bytes: &[u8]) -> String {
    encode_with(bytes, URL_SAFE, false)
}

/// Разбирает base64 в байты; пробелы по краям отбрасываются.
pub fn decode(text: &str) -> CoreResult<Vec<u8>> {
    let text = text.trim();
    let bytes = text.as_bytes();

    let body = bytes.iter().position(|&b| b == b'=').unwrap_or(bytes.len());
    let (payload, padding) = bytes.split_at(body);

    if padding.iter().any(|&b| b != b'=') {
        return Err(malformed(text, "`=` посреди строки"));
    }
    if padding.len() > 2 || (!padding.is_empty() && !bytes.len().is_multiple_of(4)) {
        return Err(malformed(text, "неверное дополнение `=`"));
    }
    if payload.len() % 4 == 1 {
        return Err(malformed(text, "оборванный последний символ"));
    }

    let mut out = Vec::with_capacity(payload.len() / 4 * 3 + 2);
    let mut buffer: u32 = 0;
    let mut filled = 0;

    for &symbol in payload {
        let value = value_of(symbol).ok_or_else(|| malformed(text, "посторонний символ"))?;
        buffer = (buffer << 6) | u32::from(value);
        filled += 6;
        if filled >= 8 {
            filled -= 8;
            out.push((buffer >> filled) as u8);
        }
    }

    Ok(out)
}

/// Разбирает base64 и проверяет длину; ошибка называет `what` и обе длины.
pub fn decode_exact(text: &str, expected: usize, what: &'static str) -> CoreResult<Vec<u8>> {
    let bytes = decode(text)?;
    if bytes.len() != expected {
        return Err(CoreError::InvalidEncoding {
            format: "base64",
            reason: format!("{what}: длина {} вместо {expected} байт", bytes.len()),
        });
    }
    Ok(bytes)
}

/// Ошибка разбора; сама строка не попадает в сообщение: это почти всегда ключ (§5.2).
fn malformed(text: &str, reason: &str) -> CoreError {
    CoreError::InvalidEncoding {
        format: "base64",
        reason: format!("{reason} (длина {})", text.len()),
    }
}

/// Значение символа в обоих алфавитах сразу.
fn value_of(symbol: u8) -> Option<u8> {
    match symbol {
        b'A'..=b'Z' => Some(symbol - b'A'),
        b'a'..=b'z' => Some(symbol - b'a' + 26),
        b'0'..=b'9' => Some(symbol - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Сборка для обоих алфавитов.
fn encode_with(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let block = match chunk {
            [a] => u32::from(*a) << 16,
            [a, b] => (u32::from(*a) << 16) | (u32::from(*b) << 8),
            [a, b, c] => (u32::from(*a) << 16) | (u32::from(*b) << 8) | u32::from(*c),
            _ => continue,
        };

        let symbols = chunk.len() + 1;
        for index in 0..symbols {
            let shift = 18 - index * 6;
            out.push(alphabet[((block >> shift) & 0x3F) as usize] as char);
        }
        if pad {
            for _ in symbols..4 {
                out.push('=');
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Вектора из RFC 4648, §10.
    const RFC: &[(&str, &str)] = &[
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn rfc_vectors_encode() {
        for (plain, encoded) in RFC {
            assert_eq!(encode(plain.as_bytes()), *encoded, "{plain}");
        }
    }

    #[test]
    fn rfc_vectors_decode() {
        for (plain, encoded) in RFC {
            assert_eq!(decode(encoded).unwrap(), plain.as_bytes(), "{encoded}");
        }
    }

    #[test]
    fn padding_is_optional() {
        assert_eq!(decode("Zm9vYmE").unwrap(), b"fooba");
        assert_eq!(decode("Zm9vYmE=").unwrap(), b"fooba");
    }

    #[test]
    fn both_alphabets_are_accepted() {
        let bytes = [0xFB, 0xEF, 0xBE];
        assert_eq!(encode(&bytes), "++++");
        assert_eq!(encode_url(&bytes), "----");
        assert_eq!(decode("++++").unwrap(), bytes);
        assert_eq!(decode("----").unwrap(), bytes);
    }

    #[test]
    fn url_alphabet_has_no_padding() {
        assert_eq!(encode_url(b"f"), "Zg");
        assert_eq!(encode_url(b"fo"), "Zm8");
    }

    #[test]
    fn surrounding_whitespace_is_not_a_mistake() {
        assert_eq!(decode("  Zm9vYmFy\n").unwrap(), b"foobar");
    }

    #[test]
    fn a_stray_symbol_is_rejected() {
        assert!(decode("Zm9v YmFy").is_err(), "пробел посреди строки");
        assert!(decode("Zm9v!mFy").is_err());
    }

    #[test]
    fn padding_in_the_middle_is_rejected() {
        assert!(decode("Zm=9vYmFy").is_err());
    }

    #[test]
    fn a_dangling_symbol_is_rejected() {
        assert!(decode("Z").is_err());
        assert!(decode("Zm9vZ").is_err());
    }

    #[test]
    fn too_much_padding_is_rejected() {
        assert!(decode("Zg===").is_err());
    }

    #[test]
    fn trailing_bits_are_forgiven() {
        assert_eq!(decode("Zm9vYmE").unwrap(), decode("Zm9vYmF").unwrap());
    }

    #[test]
    fn a_key_of_the_wrong_length_says_so() {
        let short = encode(&[0u8; 16]);
        let err = decode_exact(&short, 32, "ключ").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("16"), "{text}");
        assert!(text.contains("32"), "{text}");

        let right = encode(&[0u8; 32]);
        assert_eq!(decode_exact(&right, 32, "ключ").unwrap().len(), 32);
    }

    #[test]
    fn a_broken_key_never_shows_up_in_the_message() {
        let err = decode("секретный!ключ").unwrap_err();
        assert!(!err.to_string().contains("ключ"), "{err}");
    }

    #[test]
    fn round_trip_holds_for_every_length() {
        for len in 0..=64usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            assert_eq!(decode(&encode(&bytes)).unwrap(), bytes, "длина {len}");
            assert_eq!(decode(&encode_url(&bytes)).unwrap(), bytes, "длина {len}");
        }
    }
}
