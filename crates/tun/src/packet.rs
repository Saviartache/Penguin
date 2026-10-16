//! Версия IP-пакета по первому байту.

/// Версия протокола сети; `None` — буфер пуст или версия неизвестна.
pub fn ip_version(packet: &[u8]) -> Option<u8> {
    match packet.first()? >> 4 {
        version @ (4 | 6) => Some(version),
        _ => None,
    }
}

/// Это пакет IPv4.
pub fn is_ipv4(packet: &[u8]) -> bool {
    ip_version(packet) == Some(4)
}

/// Это пакет IPv6.
pub fn is_ipv6(packet: &[u8]) -> bool {
    ip_version(packet) == Some(6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_version_nibble() {
        assert_eq!(ip_version(&[0x45, 0, 0, 20]), Some(4));
        assert_eq!(ip_version(&[0x60, 0, 0, 0]), Some(6));
    }

    #[test]
    fn rejects_empty_and_garbage() {
        assert_eq!(ip_version(&[]), None);
        assert_eq!(ip_version(&[0x80]), None);
    }

    #[test]
    fn helpers_agree_with_the_version() {
        assert!(is_ipv4(&[0x45]));
        assert!(!is_ipv6(&[0x45]));
        assert!(is_ipv6(&[0x60]));
        assert!(!is_ipv4(&[0x60]));
    }
}
