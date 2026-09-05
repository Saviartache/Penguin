//! `server_name` (0) — RFC 6066, §3.
//!
//! Формат вложен на три уровня (расширение → список имён → одно имя), потому
//! что RFC оставил место под несколько имён разных типов. Ни один клиент
//! этим не пользуется: имя ровно одно, и тип у него всегда `host_name` (0).

const EXTENSION_TYPE: u16 = 0;

/// Кодирует `server_name`.
pub fn encode(host: &str) -> Vec<u8> {
    let name_len = host.len();
    let mut out = Vec::with_capacity(9 + name_len);
    out.extend_from_slice(&EXTENSION_TYPE.to_be_bytes());
    out.extend_from_slice(&((name_len + 5) as u16).to_be_bytes());
    out.extend_from_slice(&((name_len + 3) as u16).to_be_bytes());
    out.push(0); // host_name
    out.extend_from_slice(&(name_len as u16).to_be_bytes());
    out.extend_from_slice(host.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hostname_is_wrapped_in_three_length_prefixes() {
        let bytes = encode("example.com");
        assert_eq!(&bytes[0..2], &0u16.to_be_bytes());
        assert_eq!(&bytes[2..4], &16u16.to_be_bytes(), "заголовок расширения");
        assert_eq!(&bytes[4..6], &14u16.to_be_bytes(), "список имён");
        assert_eq!(bytes[6], 0, "тип имени: host_name");
        assert_eq!(&bytes[7..9], &11u16.to_be_bytes(), "длина самого имени");
        assert_eq!(&bytes[9..], "example.com".as_bytes());
    }
}
