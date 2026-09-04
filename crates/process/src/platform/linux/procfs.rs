//! Таблицы соединений из `/proc/net`.
//!
//! Ядро не отвечает на вопрос «чей этот порт» напрямую: в таблице лежит номер
//! inode сокета, а по нему владелец ищется уже обходом `/proc/*/fd`
//! ([`super::fd`]). Отсюда и устройство файла — здесь только первая половина.
//!
//! Адреса записаны шестнадцатеричным числом в порядке байт **машины**, а не
//! сети: файл пишет то же ядро, что и читает наш процесс, поэтому разбор идёт
//! через `to_ne_bytes` и остаётся верным на любой архитектуре.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use penguin_core::network::Network;

/// Одна запись таблицы: чей локальный адрес.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Entry {
    /// Локальный адрес соединения.
    pub(super) local: SocketAddr,
    /// Номер inode сокета — по нему ищется владелец.
    pub(super) inode: u64,
}

/// Снимок таблицы соединений.
///
/// Читаются обе таблицы, IPv4 и IPv6: сокет, открытый как двухсемейный,
/// система показывает только во второй, а трафик по нему идёт и по IPv4.
pub(super) fn snapshot(network: Network) -> Vec<Entry> {
    let files: [&str; 2] = match network {
        Network::Tcp => ["/proc/net/tcp", "/proc/net/tcp6"],
        Network::Udp => ["/proc/net/udp", "/proc/net/udp6"],
    };

    let mut entries = Vec::new();
    for file in files {
        // Файла может не быть вовсе: ядро без IPv6 не создаёт `tcp6`.
        if let Ok(text) = std::fs::read_to_string(file) {
            entries.extend(parse(&text));
        }
    }
    entries
}

/// Разбирает таблицу.
///
/// Первая строка — заголовок столбцов, и пропускается она по месту: имена
/// столбцов ядро не переводит, но и опираться на них незачем.
fn parse(text: &str) -> Vec<Entry> {
    text.lines().skip(1).filter_map(parse_line).collect()
}

/// Разбирает строку таблицы.
fn parse_line(line: &str) -> Option<Entry> {
    /// Номер столбца с локальным адресом.
    const LOCAL: usize = 1;
    /// Номер столбца с inode.
    const INODE: usize = 9;

    let fields: Vec<&str> = line.split_whitespace().collect();
    let local = parse_address(fields.get(LOCAL)?)?;
    let inode = fields.get(INODE)?.parse().ok()?;

    Some(Entry { local, inode })
}

/// Разбирает адрес вида `0100007F:0035`.
fn parse_address(field: &str) -> Option<SocketAddr> {
    let (address, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;

    let address = match address.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(address)?)),
        32 => {
            let mut octets = [0u8; 16];
            let (groups, _) = address.as_bytes().as_chunks::<8>();
            for (group, slot) in groups.iter().zip(octets.as_chunks_mut::<4>().0) {
                slot.copy_from_slice(&word(std::str::from_utf8(group).ok()?)?);
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        // Строка не той длины — не адрес, а мусор или чужой формат.
        _ => return None,
    };

    Some(SocketAddr::new(address, port))
}

/// Четыре байта адреса из восьми шестнадцатеричных цифр.
///
/// Ядро печатает их числом в порядке байт машины, поэтому обратно они
/// раскладываются `to_ne_bytes`, а не `to_be_bytes`.
fn word(hex: &str) -> Option<[u8; 4]> {
    Some(u32::from_str_radix(hex, 16).ok()?.to_ne_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Строка из настоящего `/proc/net/tcp`.
    const LINE: &str = "   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 \
                        00:00000000 00000000     0        0 24680 1 0000000000000000 100 0 0 10 0";

    #[test]
    fn reads_an_address_and_an_inode() {
        let entry = parse_line(LINE).expect("строка разбирается");
        assert_eq!(
            entry.local,
            "127.0.0.1:53".parse::<SocketAddr>().expect("адрес")
        );
        assert_eq!(entry.inode, 24680);
    }

    #[test]
    fn a_port_is_hexadecimal() {
        // `1F90` — это 8080, а не 1990: десятичный разбор увёл бы правило к
        // чужому соединению.
        let address = parse_address("0100007F:1F90").expect("адрес");
        assert_eq!(address.port(), 8080);
    }

    #[test]
    fn the_wildcard_address_reads_as_such() {
        let address = parse_address("00000000:0050").expect("адрес");
        assert!(address.ip().is_unspecified());
        assert_eq!(address.port(), 80);
    }

    #[test]
    fn an_ipv6_address_is_read_by_groups() {
        // Каждая четвёрка байт записана отдельным числом; разбор всей строки
        // одним числом дал бы адрес с переставленными половинами.
        let address = parse_address("00000000000000000000000001000000:0050").expect("адрес");
        assert_eq!(address.ip(), "::1".parse::<IpAddr>().expect("адрес"));
    }

    #[test]
    fn the_header_is_not_an_entry() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue\n";
        assert!(parse(text).is_empty());
    }

    #[test]
    fn a_truncated_line_is_skipped() {
        // Таблица читается на ходу и может оборваться на середине строки.
        assert!(parse_line("   0: 0100007F:0035 00000000:0000 0A").is_none());
        assert!(parse_line("").is_none());
    }

    #[test]
    fn a_field_of_the_wrong_length_is_not_an_address() {
        assert!(parse_address("0100:0035").is_none());
        assert!(parse_address("0100007F").is_none());
    }
}
