//! SNI из QUIC Initial.
//!
//! Только опознание заголовка Initial: расшифровка (RFC 9001 §5.2) потребовала
//! бы AEAD+HKDF в крейте без криптографии. Имя для QUIC берётся из fake-IP
//! ([`penguin_dns::fakeip`]).

/// Длинный заголовок: старшие биты формы и фиксированный (RFC 9000 §17.2).
const LONG_HEADER_MASK: u8 = 0xC0;

/// Тип пакета `Initial` в битах 4–5 первого байта (QUIC v1).
const PACKET_TYPE_INITIAL: u8 = 0x00;

/// Версия QUIC v1.
const QUIC_V1: u32 = 0x0000_0001;

/// Похоже ли это на пакет QUIC Initial.
pub fn is_initial(data: &[u8]) -> bool {
    let Some(&first) = data.first() else {
        return false;
    };

    if first & LONG_HEADER_MASK != LONG_HEADER_MASK {
        return false;
    }
    if (first >> 4) & 0x03 != PACKET_TYPE_INITIAL {
        return false;
    }

    let Some(version) = data.get(1..5) else {
        return false;
    };
    let version = u32::from_be_bytes([version[0], version[1], version[2], version[3]]);
    version == QUIC_V1
}

/// Имя из QUIC Initial: пока всегда `None` (см. заголовок модуля).
pub fn extract_sni(data: &[u8]) -> Option<&str> {
    if is_initial(data) {
        tracing::trace!("QUIC Initial опознан, имя не читается — полагаемся на fake-IP");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Заголовок пакета Initial: форма, версия, длины идентификаторов.
    fn initial_header() -> Vec<u8> {
        let mut packet = vec![0xC0];
        packet.extend_from_slice(&QUIC_V1.to_be_bytes());
        packet.push(8); // длина идентификатора назначения
        packet.extend_from_slice(&[0xAB; 8]);
        packet.push(0); // длина идентификатора источника
        packet
    }

    #[test]
    fn recognises_an_initial_packet() {
        assert!(is_initial(&initial_header()));
    }

    #[test]
    fn rejects_short_header_packets() {
        assert!(!is_initial(&[0x40, 1, 2, 3, 4, 5]));
    }

    #[test]
    fn rejects_other_versions() {
        let mut packet = initial_header();
        packet[1..5].copy_from_slice(&0xFACE_FEED_u32.to_be_bytes());
        assert!(!is_initial(&packet));
    }

    #[test]
    fn rejects_truncated_input() {
        let packet = initial_header();
        for cut in 0..5 {
            assert!(!is_initial(&packet[..cut]));
        }
    }

    #[test]
    fn extraction_is_honest_about_not_working() {
        assert_eq!(extract_sni(&initial_header()), None);
        assert_eq!(extract_sni(&[0u8; 32]), None);
    }
}
