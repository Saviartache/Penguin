//! Ответ на ping из тоннеля: ICMP протоколы не возят, и без ответа `ping` выглядел бы обрывом
//! связи. Отвечает сам стек, как sing-box и Clash: время — до стека, а не до узла.

use std::net::Ipv6Addr;

use bytes::BytesMut;

use super::checksum;
use super::parse::{PROTO_ICMP, PROTO_ICMPV6};

const ECHO_REQUEST_V4: u8 = 8;
const ECHO_REPLY_V4: u8 = 0;
const ECHO_REQUEST_V6: u8 = 128;
const ECHO_REPLY_V6: u8 = 129;

/// Время жизни ответа.
const TTL: u8 = 64;

/// Превращает эхо-запрос в ответ на месте; `false` — не эхо-запрос, пакет не тронут.
pub fn answer(packet: &mut BytesMut) -> bool {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => answer_v4(packet),
        Some(6) => answer_v6(packet),
        _ => false,
    }
}

fn answer_v4(packet: &mut BytesMut) -> bool {
    if packet.len() < 20 || packet[9] != PROTO_ICMP {
        return false;
    }
    let header = usize::from(packet[0] & 0x0F) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    // Фрагменты не собираются.
    let fragmented = u16::from_be_bytes([packet[6], packet[7]]) & 0x3FFF != 0;
    if header < 20 || total < header + 8 || total > packet.len() || fragmented {
        return false;
    }
    if packet[header] != ECHO_REQUEST_V4 || packet[header + 1] != 0 {
        return false;
    }

    packet.truncate(total);
    swap_addresses(packet, 12, 4);
    packet[8] = TTL;
    let sum = checksum::ipv4_header(&packet[..header]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());

    packet[header] = ECHO_REPLY_V4;
    packet[header + 2..header + 4].fill(0);
    let sum = checksum::finish(checksum::sum(&packet[header..]));
    packet[header + 2..header + 4].copy_from_slice(&sum.to_be_bytes());
    true
}

fn answer_v6(packet: &mut BytesMut) -> bool {
    // Заголовки расширения не разбираются.
    if packet.len() < 48 || packet[6] != PROTO_ICMPV6 {
        return false;
    }
    let end = 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if end < 48 || end > packet.len() || packet[40] != ECHO_REQUEST_V6 || packet[41] != 0 {
        return false;
    }

    packet.truncate(end);
    swap_addresses(packet, 8, 16);
    packet[7] = TTL;

    packet[40] = ECHO_REPLY_V6;
    packet[42..44].fill(0);
    let source = address_v6(&packet[8..24]);
    let destination = address_v6(&packet[24..40]);
    let length = (end - 40) as u32;
    let total = checksum::pseudo_v6(source, destination, PROTO_ICMPV6, length)
        + checksum::sum(&packet[40..]);
    packet[42..44].copy_from_slice(&checksum::finish(total).to_be_bytes());
    true
}

/// Меняет местами источник и назначение, лежащие подряд с `start`.
fn swap_addresses(packet: &mut [u8], start: usize, len: usize) {
    let (source, destination) = packet[start..start + 2 * len].split_at_mut(len);
    source.swap_with_slice(destination);
}

fn address_v6(bytes: &[u8]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(bytes);
    Ipv6Addr::from(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Эхо-запрос IPv4 с верными суммами.
    fn request_v4() -> BytesMut {
        let icmp_len = 8 + 4;
        let mut packet = vec![0u8; 20 + icmp_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((20 + icmp_len) as u16).to_be_bytes());
        packet[8] = 63;
        packet[9] = PROTO_ICMP;
        packet[12..16].copy_from_slice(&[198, 18, 0, 1]);
        packet[16..20].copy_from_slice(&[198, 18, 0, 35]);
        let sum = checksum::ipv4_header(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());

        packet[20] = ECHO_REQUEST_V4;
        packet[24..28].copy_from_slice(&[0x12, 0x34, 0x00, 0x07]);
        packet[28..32].copy_from_slice(b"ping");
        let sum = checksum::finish(checksum::sum(&packet[20..]));
        packet[22..24].copy_from_slice(&sum.to_be_bytes());
        BytesMut::from(&packet[..])
    }

    #[test]
    fn an_echo_request_becomes_a_valid_reply() {
        let mut packet = request_v4();
        assert!(answer(&mut packet));

        assert_eq!(
            &packet[12..16],
            &[198, 18, 0, 35],
            "отвечает тот, кого спросили"
        );
        assert_eq!(&packet[16..20], &[198, 18, 0, 1]);
        assert_eq!(packet[20], ECHO_REPLY_V4);
        assert_eq!(
            &packet[24..32],
            b"\x12\x34\x00\x07ping",
            "номер и данные не те"
        );
        assert_eq!(
            checksum::finish(checksum::sum(&packet[..20])),
            0,
            "сумма IP"
        );
        assert_eq!(
            checksum::finish(checksum::sum(&packet[20..])),
            0,
            "сумма ICMP"
        );
    }

    #[test]
    fn padding_after_the_packet_is_dropped() {
        let mut packet = request_v4();
        let len = packet.len();
        packet.extend_from_slice(&[0xFF; 6]);
        assert!(answer(&mut packet));
        assert_eq!(packet.len(), len);
    }

    #[test]
    fn a_reply_or_other_traffic_is_left_alone() {
        let mut reply = request_v4();
        reply[20] = ECHO_REPLY_V4;
        let before = reply.clone();
        assert!(!answer(&mut reply));
        assert_eq!(reply, before);

        let mut udp = request_v4();
        udp[9] = super::super::parse::PROTO_UDP;
        assert!(!answer(&mut udp));
    }

    #[test]
    fn an_ipv6_echo_request_becomes_a_valid_reply() {
        let source = Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 1);
        let destination = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let mut packet = [0u8; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        packet[6] = PROTO_ICMPV6;
        packet[7] = 63;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40] = ECHO_REQUEST_V6;
        packet[44..48].copy_from_slice(&[0, 1, 0, 2]);
        let mut packet = BytesMut::from(&packet[..]);

        assert!(answer(&mut packet));
        assert_eq!(packet[40], ECHO_REPLY_V6);
        assert_eq!(&packet[8..24], &destination.octets());
        let total = checksum::pseudo_v6(destination, source, PROTO_ICMPV6, 8)
            + checksum::sum(&packet[40..]);
        assert_eq!(checksum::finish(total), 0, "сумма ICMPv6");
    }

    #[test]
    fn truncated_input_never_panics() {
        let packet = request_v4();
        for cut in 0..packet.len() {
            let _ = answer(&mut BytesMut::from(&packet[..cut]));
        }
    }
}
