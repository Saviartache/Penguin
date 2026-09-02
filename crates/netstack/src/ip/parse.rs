//! Быстрый разбор заголовков: адреса и порты нужны раньше, чем соединение
//! установлено.
//!
//! Стек TCP/IP из smoltcp разбирает пакеты сам, но решение о судьбе
//! соединения принимается **до** того, как оно установлено: по первому же
//! пакету надо понять, кому и куда, чтобы завести под него сокет. UDP же
//! через smoltcp не идёт вовсе — состояния у него нет, и заводить сокет на
//! каждую пару адресов было бы чистой тратой.
//!
//! Разбор идёт по срезу без единой копии: заголовок читается на месте.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use penguin_core::network::Network;

/// Номер протокола TCP.
pub const PROTO_TCP: u8 = 6;
/// Номер протокола UDP.
pub const PROTO_UDP: u8 = 17;
/// Номер протокола ICMP.
pub const PROTO_ICMP: u8 = 1;
/// Номер протокола ICMPv6.
pub const PROTO_ICMPV6: u8 = 58;

/// Наименьшая длина заголовка IPv4.
const IPV4_MIN_HEADER: usize = 20;
/// Длина заголовка IPv6 — она постоянная.
const IPV6_HEADER: usize = 40;

/// Разобранный пакет.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    /// Откуда.
    pub source: SocketAddr,
    /// Куда.
    pub destination: SocketAddr,
    /// Вид трафика.
    pub network: Network,
    /// Флаг `SYN` без `ACK` — начало соединения.
    ///
    /// Только для TCP; для UDP всегда `false`.
    pub is_syn: bool,
    /// Данные после транспортного заголовка.
    pub payload: &'a [u8],
}

/// Разбирает IP-пакет.
///
/// `None` — не IP, обрезано, или протокол не тот, которым мы занимаемся.
/// Всё это обычный фон: по интерфейсу ходят ICMP, широковещательные
/// объявления и что угодно ещё.
pub fn parse(packet: &[u8]) -> Option<Packet<'_>> {
    match packet.first()? >> 4 {
        4 => parse_v4(packet),
        6 => parse_v6(packet),
        _ => None,
    }
}

fn parse_v4(packet: &[u8]) -> Option<Packet<'_>> {
    if packet.len() < IPV4_MIN_HEADER {
        return None;
    }

    // Длина заголовка задаётся младшими четырьмя битами первого байта в
    // тридцатидвухбитных словах: пакеты с параметрами длиннее двадцати байт.
    let header_len = usize::from(packet[0] & 0x0F) * 4;
    if header_len < IPV4_MIN_HEADER || packet.len() < header_len {
        return None;
    }

    // Фрагмент не первый — транспортного заголовка в нём нет. Смещение
    // лежит в младших тринадцати битах поля флагов и смещения.
    let fragment_offset = u16::from_be_bytes([packet[6], packet[7]]) & 0x1FFF;
    if fragment_offset != 0 {
        return None;
    }

    let protocol = packet[9];
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    // Общая длина из заголовка может быть меньше того, что пришло: драйвер
    // иногда дополняет пакет до минимального размера кадра.
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let end = total_len.clamp(header_len, packet.len());

    transport(
        &packet[header_len..end],
        protocol,
        IpAddr::V4(source),
        IpAddr::V4(destination),
    )
}

fn parse_v6(packet: &[u8]) -> Option<Packet<'_>> {
    if packet.len() < IPV6_HEADER {
        return None;
    }

    // Заголовков расширения не разбираем: в тоннеле они не встречаются, а
    // делать вид, что разобрали, хуже, чем честно пропустить пакет мимо.
    let protocol = packet[6];

    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);

    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let end = (IPV6_HEADER + payload_len).min(packet.len());

    transport(
        &packet[IPV6_HEADER..end],
        protocol,
        IpAddr::V6(source),
        IpAddr::V6(destination),
    )
}

/// Разбирает транспортный заголовок.
fn transport<'a>(
    body: &'a [u8],
    protocol: u8,
    source: IpAddr,
    destination: IpAddr,
) -> Option<Packet<'a>> {
    match protocol {
        PROTO_TCP => {
            if body.len() < 20 {
                return None;
            }
            let source_port = u16::from_be_bytes([body[0], body[1]]);
            let destination_port = u16::from_be_bytes([body[2], body[3]]);

            // Смещение данных — старшие четыре бита тринадцатого байта, в
            // тридцатидвухбитных словах.
            let data_offset = usize::from(body[12] >> 4) * 4;
            let flags = body[13];
            let is_syn = flags & 0x02 != 0 && flags & 0x10 == 0;

            let payload = body.get(data_offset.max(20)..).unwrap_or(&[]);

            Some(Packet {
                source: SocketAddr::new(source, source_port),
                destination: SocketAddr::new(destination, destination_port),
                network: Network::Tcp,
                is_syn,
                payload,
            })
        }
        PROTO_UDP => {
            if body.len() < 8 {
                return None;
            }
            let source_port = u16::from_be_bytes([body[0], body[1]]);
            let destination_port = u16::from_be_bytes([body[2], body[3]]);

            // Длина в заголовке UDP считается вместе с ним самим.
            let length = u16::from_be_bytes([body[4], body[5]]) as usize;
            let end = length.clamp(8, body.len());

            Some(Packet {
                source: SocketAddr::new(source, source_port),
                destination: SocketAddr::new(destination, destination_port),
                network: Network::Udp,
                is_syn: false,
                payload: &body[8..end],
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Собирает пакет IPv4 с указанным транспортом.
    fn ipv4(protocol: u8, body: &[u8]) -> Vec<u8> {
        let total = 20 + body.len();
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[93, 184, 216, 34]);
        packet.extend_from_slice(body);
        packet
    }

    fn tcp_header(source: u16, destination: u16, flags: u8) -> Vec<u8> {
        let mut body = vec![0u8; 20];
        body[0..2].copy_from_slice(&source.to_be_bytes());
        body[2..4].copy_from_slice(&destination.to_be_bytes());
        body[12] = 5 << 4; // смещение данных: 20 байт
        body[13] = flags;
        body
    }

    fn udp_datagram(source: u16, destination: u16, payload: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; 8];
        body[0..2].copy_from_slice(&source.to_be_bytes());
        body[2..4].copy_from_slice(&destination.to_be_bytes());
        body[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        body.extend_from_slice(payload);
        body
    }

    #[test]
    fn parses_a_tcp_syn() {
        let packet = ipv4(PROTO_TCP, &tcp_header(50000, 443, 0x02));
        let parsed = parse(&packet).expect("разбирается");

        assert_eq!(parsed.network, Network::Tcp);
        assert_eq!(parsed.source.port(), 50000);
        assert_eq!(parsed.destination.port(), 443);
        assert_eq!(parsed.destination.ip().to_string(), "93.184.216.34");
        assert!(parsed.is_syn, "начало соединения не опознано");
    }

    #[test]
    fn syn_ack_is_not_a_new_connection() {
        // Ответ сервера тоже несёт `SYN`, но новым соединением не является.
        let packet = ipv4(PROTO_TCP, &tcp_header(443, 50000, 0x12));
        assert!(!parse(&packet).expect("разбирается").is_syn);
    }

    #[test]
    fn parses_udp_payload() {
        let packet = ipv4(PROTO_UDP, &udp_datagram(50000, 53, b"query"));
        let parsed = parse(&packet).expect("разбирается");
        assert_eq!(parsed.network, Network::Udp);
        assert_eq!(parsed.payload, b"query");
    }

    #[test]
    fn respects_the_length_field_over_the_buffer() {
        // Драйвер дополняет короткий пакет до минимального размера кадра;
        // лишние байты не должны попасть в данные.
        let mut packet = ipv4(PROTO_UDP, &udp_datagram(1, 53, b"ab"));
        packet.extend_from_slice(&[0xFF; 40]);
        assert_eq!(parse(&packet).expect("разбирается").payload, b"ab");
    }

    #[test]
    fn handles_options_in_the_header() {
        // Заголовок с параметрами длиннее двадцати байт; транспорт начинается
        // после него, а не по фиксированному смещению.
        let mut packet = ipv4(PROTO_TCP, &tcp_header(50000, 443, 0x02));
        packet[0] = 0x46; // 24 байта заголовка
        packet.splice(20..20, [0u8; 4]);
        let total = packet.len() as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());

        let parsed = parse(&packet).expect("разбирается");
        assert_eq!(parsed.destination.port(), 443);
    }

    #[test]
    fn skips_non_first_fragments() {
        // Транспортного заголовка во втором фрагменте нет; разбирать там
        // нечего, и притворяться, что разобрали, нельзя.
        let mut packet = ipv4(PROTO_TCP, &tcp_header(50000, 443, 0x02));
        packet[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
        assert!(parse(&packet).is_none());
    }

    #[test]
    fn parses_ipv6() {
        let body = udp_datagram(50000, 53, b"query");
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(body.len() as u16).to_be_bytes());
        packet[6] = PROTO_UDP;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        packet.extend_from_slice(&body);

        let parsed = parse(&packet).expect("разбирается");
        assert!(parsed.destination.is_ipv6());
        assert_eq!(parsed.destination.port(), 53);
        assert_eq!(parsed.payload, b"query");
    }

    #[test]
    fn ignores_other_protocols() {
        // ICMP по интерфейсу ходит постоянно; это фон, а не ошибка.
        assert!(parse(&ipv4(PROTO_ICMP, &[0u8; 8])).is_none());
    }

    #[test]
    fn truncated_input_never_panics() {
        let packet = ipv4(PROTO_TCP, &tcp_header(50000, 443, 0x02));
        for cut in 0..packet.len() {
            let _ = parse(&packet[..cut]);
        }
    }

    #[test]
    fn garbage_never_panics() {
        // Заголовки приходят из сети: любое число в них может быть любым.
        let mut packet = ipv4(PROTO_TCP, &tcp_header(50000, 443, 0x02));
        for index in 0..packet.len() {
            let original = packet[index];
            for value in [0x00, 0x0F, 0xF0, 0xFF] {
                packet[index] = value;
                let _ = parse(&packet);
            }
            packet[index] = original;
        }
    }
}
