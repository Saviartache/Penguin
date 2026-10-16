//! Контрольные суммы IPv4, TCP, UDP (RFC 1071); собираемые нами пакеты с неверной суммой система молча выбросит.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Складывает байты как 16-битные слова; переносы копятся в старшей половине `u32`.
pub fn sum(data: &[u8]) -> u32 {
    let mut total = 0u32;
    let (words, tail) = data.as_chunks::<2>();

    for word in words {
        total += u32::from(u16::from_be_bytes(*word));
    }
    // Нечётный хвост дополняется нулём справа.
    if let [last] = tail {
        total += u32::from(u16::from_be_bytes([*last, 0]));
    }
    total
}

/// Сворачивает переносы и отрицает — готовая контрольная сумма.
pub fn finish(mut total: u32) -> u16 {
    while total >> 16 != 0 {
        total = (total & 0xFFFF) + (total >> 16);
    }
    !(total as u16)
}

/// Контрольная сумма заголовка IPv4; байты 10–11 (само поле) пропускаются.
pub fn ipv4_header(header: &[u8]) -> u16 {
    finish(sum(&header[..10]) + sum(&header[12..]))
}

/// Псевдозаголовок IPv4 для TCP и UDP.
pub fn pseudo_v4(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, length: u16) -> u32 {
    let mut total = sum(&source.octets()) + sum(&destination.octets());
    total += u32::from(protocol);
    total += u32::from(length);
    total
}

/// Псевдозаголовок IPv6.
pub fn pseudo_v6(source: Ipv6Addr, destination: Ipv6Addr, protocol: u8, length: u32) -> u32 {
    let mut total = sum(&source.octets()) + sum(&destination.octets());
    total += length >> 16;
    total += length & 0xFFFF;
    total += u32::from(protocol);
    total
}

/// Контрольная сумма UDP поверх IPv4; ноль заменяется на `0xFFFF` (ноль в поле — «не считалась»).
pub fn udp_v4(source: Ipv4Addr, destination: Ipv4Addr, datagram: &[u8]) -> u16 {
    let total = pseudo_v4(source, destination, 17, datagram.len() as u16) + sum(datagram);
    match finish(total) {
        0 => 0xFFFF,
        value => value,
    }
}

/// Контрольная сумма UDP поверх IPv6 (обязательна).
pub fn udp_v6(source: Ipv6Addr, destination: Ipv6Addr, datagram: &[u8]) -> u16 {
    let total = pseudo_v6(source, destination, 17, datagram.len() as u32) + sum(datagram);
    match finish(total) {
        0 => 0xFFFF,
        value => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc_1071_example() {
        // RFC 1071, §3.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(finish(sum(&data)), 0x220d);
    }

    #[test]
    fn odd_length_pads_on_the_right() {
        assert_eq!(sum(&[0x12]), 0x1200);
        assert_eq!(sum(&[0x12, 0x00]), 0x1200);
    }

    #[test]
    fn verifies_a_real_ipv4_header() {
        let header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(ipv4_header(&header), 0xb861);
        assert_eq!(finish(sum(&header)), 0);
    }

    #[test]
    fn udp_checksum_never_reports_zero() {
        let source = Ipv4Addr::new(1, 2, 3, 4);
        let destination = Ipv4Addr::new(5, 6, 7, 8);
        for length in 0..200usize {
            let datagram = vec![0x5A; length];
            assert_ne!(udp_v4(source, destination, &datagram), 0);
        }
    }

    #[test]
    fn udp_checksum_detects_address_substitution() {
        let datagram = [0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00];
        let original = udp_v4(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            &datagram,
        );
        let substituted = udp_v4(
            Ipv4Addr::new(1, 2, 3, 5),
            Ipv4Addr::new(5, 6, 7, 8),
            &datagram,
        );
        assert_ne!(original, substituted);
    }

    #[test]
    fn carries_fold_correctly() {
        let data: Vec<u8> = (0..4096).map(|byte| (byte % 251) as u8).collect();
        let total = sum(&data);
        assert_ne!(total >> 16, 0, "перенос не накопился — сворачивать нечего");

        // Сумма вместе с контрольной суммой даёт ноль.
        let checksum = finish(total);
        assert_eq!(finish(total + u32::from(checksum)), 0);
    }

    #[test]
    fn v6_pseudo_header_uses_full_length() {
        let source = Ipv6Addr::LOCALHOST;
        let destination = Ipv6Addr::LOCALHOST;
        let short = pseudo_v6(source, destination, 17, 0x0000_0010);
        let long = pseudo_v6(source, destination, 17, 0x0001_0010);
        assert_ne!(short, long);
    }
}
