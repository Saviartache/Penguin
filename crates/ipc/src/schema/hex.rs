//! Байты в JSON строкой hex: массив чисел раздул бы кусок вчетверо.

use serde::{Deserialize, Deserializer, Serializer, de};

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Пишет байты строкой.
pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    serializer.serialize_str(&text)
}

/// Читает байты из строки.
pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    // Не `&str`: из потока строку взаймы не взять.
    let text = String::deserialize(deserializer)?;
    if text.len() % 2 != 0 {
        return Err(de::Error::custom("нечётная длина hex"));
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[high, low]| Ok(nibble(high)? << 4 | nibble(low)?))
        .collect()
}

fn nibble<E: de::Error>(digit: u8) -> Result<u8, E> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        b'A'..=b'F' => Ok(digit - b'A' + 10),
        _ => Err(E::custom("не hex")),
    }
}

#[cfg(test)]
mod tests {
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Wrapped(#[serde(with = "super")] Vec<u8>);

    #[test]
    fn bytes_survive_json() {
        let bytes = Wrapped(vec![0x00, 0x0f, 0xa5, 0xff]);
        let json = serde_json::to_string(&bytes).expect("сериализуется");
        assert_eq!(json, "\"000fa5ff\"");
        assert_eq!(
            serde_json::from_str::<Wrapped>(&json).expect("разбирается"),
            bytes
        );
    }

    #[test]
    fn broken_hex_is_refused() {
        assert!(serde_json::from_str::<Wrapped>("\"abc\"").is_err());
        assert!(serde_json::from_str::<Wrapped>("\"zz\"").is_err());
    }
}
