//! Датаграмма внутри потока: свой адрес туда и другой обратно.
//!
//! ```text
//!  туда    [0x01][адрес][данные]
//!  обратно       [адрес][данные]
//! ```
//!
//! Одна датаграмма — **один кусок** общего кадра. Границу даёт не длина
//! внутри посылки, а сам кусок: длины здесь нет вовсе, и всё, что осталось
//! после адреса, и есть данные. Поэтому читать канал можно только кусками
//! (см. `read_chunk` у [`penguin_transport::aead::ChunkStream`]) — байтовым
//! чтением две датаграммы склеились бы в одну.
//!
//! # Записей адреса две, и они разные
//!
//! Туда:
//!
//! ```text
//!  домен  [длина][имя][порт]          длина не бывает нулём
//!  IPv4   [0x00][0x04][4 байта][порт]
//!  IPv6   [0x00][0x06][16 байт][порт]
//! ```
//!
//! Ноль на месте длины имени и означает «дальше не имя, а адрес». Обратно
//! сервер шлёт только числовой адрес, и уже без этого нуля:
//!
//! ```text
//!  IPv4   [0x04][4 байта][порт]
//!  IPv6   [0x06][16 байт][порт]
//! ```
//!
//! Ни с SOCKS5, ни с чем-либо ещё в дереве это не совпадает. Разбор адреса
//! отсюда общим сделать нельзя, и своя запись у Snell не одна, а две.

use std::net::IpAddr;

use penguin_core::address::{Address, SocketAddress};

use crate::error::{SnellError, SnellResult};

/// Первый байт каждой посылки в сторону сервера.
pub const FORWARD: u8 = 0x01;

/// Числовой адрес IPv4.
pub const ATYP_IPV4: u8 = 0x04;

/// Числовой адрес IPv6.
pub const ATYP_IPV6: u8 = 0x06;

/// Собирает посылку в сторону сервера.
pub fn seal(target: &SocketAddress, payload: &[u8]) -> SnellResult<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + address_len(target) + payload.len());
    out.push(FORWARD);
    encode_address(target, &mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

/// Дописывает адрес в записи «туда».
pub fn encode_address(address: &SocketAddress, out: &mut Vec<u8>) -> SnellResult<()> {
    match &address.host {
        Address::Domain(domain) => {
            let bytes = domain.as_bytes();
            let len = u8::try_from(bytes.len())
                .map_err(|_| SnellError::address(format!("имя длиной {} байт", bytes.len())))?;
            if len == 0 {
                return Err(SnellError::address("пустое имя"));
            }
            out.push(len);
            out.extend_from_slice(bytes);
        }
        Address::Ip(IpAddr::V4(ip)) => {
            out.push(0x00);
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            out.push(0x00);
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&address.port.to_be_bytes());
    Ok(())
}

/// Сколько байт займёт адрес в записи «туда».
pub fn address_len(address: &SocketAddress) -> usize {
    match &address.host {
        Address::Domain(domain) => 1 + domain.len() + 2,
        Address::Ip(IpAddr::V4(_)) => 2 + 4 + 2,
        Address::Ip(IpAddr::V6(_)) => 2 + 16 + 2,
    }
}

/// Разбирает посылку, пришедшую от сервера: адрес и данные за ним.
///
/// Имён здесь не бывает — сервер шлёт только числовой адрес.
pub fn open(chunk: &[u8]) -> SnellResult<(SocketAddress, &[u8])> {
    let Some((&atyp, rest)) = chunk.split_first() else {
        return Err(SnellError::malformed("пустая посылка"));
    };

    let (host, len) = match atyp {
        ATYP_IPV4 => match rest.first_chunk::<4>() {
            Some(octets) => (Address::Ip(IpAddr::from(*octets)), 4),
            None => return Err(SnellError::malformed("адрес IPv4 не поместился")),
        },
        ATYP_IPV6 => match rest.first_chunk::<16>() {
            Some(octets) => (Address::Ip(IpAddr::from(*octets)), 16),
            None => return Err(SnellError::malformed("адрес IPv6 не поместился")),
        },
        other => {
            return Err(SnellError::malformed(format!(
                "тип адреса {other:#04x} в ответе: сервер шлёт только числовой"
            )));
        }
    };

    let Some(port) = rest.get(len..).and_then(<[u8]>::first_chunk::<2>) else {
        return Err(SnellError::malformed("порт не поместился"));
    };
    Ok((
        SocketAddress::new(host, u16::from_be_bytes(*port)),
        &rest[len + 2..],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_domain_goes_out_with_its_length_first() {
        let sealed = seal(&SocketAddress::domain("a.io", 53), b"query").expect("собирается");
        assert_eq!(sealed[0], FORWARD);
        assert_eq!(sealed[1], 4, "длина имени");
        assert_eq!(&sealed[2..6], b"a.io");
        assert_eq!(&sealed[6..8], &53u16.to_be_bytes());
        assert_eq!(&sealed[8..], b"query");
    }

    #[test]
    fn a_numeric_address_is_marked_by_a_zero_where_the_name_length_would_be() {
        // Ноль на месте длины имени и означает «дальше не имя».
        let target = SocketAddress::ip("203.0.113.5".parse().unwrap(), 53);
        let sealed = seal(&target, b"q").expect("собирается");

        assert_eq!(sealed[0], FORWARD);
        assert_eq!(sealed[1], 0x00, "не отмечен как числовой");
        assert_eq!(sealed[2], ATYP_IPV4);
        assert_eq!(&sealed[3..7], &[203, 0, 113, 5]);
        assert_eq!(&sealed[7..9], &53u16.to_be_bytes());
        assert_eq!(&sealed[9..], b"q");
    }

    #[test]
    fn an_ipv6_address_is_marked_the_same_way() {
        let target = SocketAddress::ip("2001:db8::1".parse().unwrap(), 53);
        let sealed = seal(&target, &[]).expect("собирается");
        assert_eq!(&sealed[1..3], &[0x00, ATYP_IPV6]);
        assert_eq!(sealed.len(), 1 + address_len(&target));
    }

    #[test]
    fn the_declared_length_matches_what_was_written() {
        for target in [
            SocketAddress::domain("example.com", 53),
            SocketAddress::ip("203.0.113.5".parse().unwrap(), 53),
            SocketAddress::ip("2001:db8::1".parse().unwrap(), 53),
        ] {
            let mut out = Vec::new();
            encode_address(&target, &mut out).expect("собирается");
            assert_eq!(out.len(), address_len(&target), "{target:?}");
        }
    }

    #[test]
    fn the_reply_carries_a_numeric_address_and_the_rest_is_data() {
        let mut wire = vec![ATYP_IPV4, 203, 0, 113, 5];
        wire.extend_from_slice(&53u16.to_be_bytes());
        wire.extend_from_slice(b"answer");

        let (from, data) = open(&wire).expect("разбирается");
        assert_eq!(
            from.host.as_ip().map(|ip| ip.to_string()).as_deref(),
            Some("203.0.113.5")
        );
        assert_eq!(from.port, 53);
        assert_eq!(data, b"answer");
    }

    #[test]
    fn an_ipv6_reply_is_read_too() {
        let mut wire = vec![ATYP_IPV6];
        wire.extend_from_slice(&[0u8; 16]);
        wire.extend_from_slice(&1u16.to_be_bytes());
        let (from, data) = open(&wire).expect("разбирается");
        assert!(from.host.as_ip().is_some_and(|ip| ip.is_ipv6()));
        assert!(data.is_empty());
    }

    #[test]
    fn an_empty_datagram_is_still_a_datagram() {
        // Пустая датаграмма UDP законна: ею проверяют достижимость.
        let mut wire = vec![ATYP_IPV4, 1, 2, 3, 4];
        wire.extend_from_slice(&1u16.to_be_bytes());
        let (_, data) = open(&wire).expect("разбирается");
        assert!(data.is_empty());
    }

    #[test]
    fn the_two_records_are_not_the_same_one() {
        // Запись туда начинается с длины имени или нуля, обратно — сразу с
        // типа. Общий разбор однажды прочитал бы одно вместо другого.
        let target = SocketAddress::ip("203.0.113.5".parse().unwrap(), 53);
        let mut there = Vec::new();
        encode_address(&target, &mut there).expect("собирается");

        let mut back = vec![ATYP_IPV4, 203, 0, 113, 5];
        back.extend_from_slice(&53u16.to_be_bytes());

        assert_ne!(there, back);
        assert_eq!(
            there.len(),
            back.len() + 1,
            "лишний ноль только в записи туда"
        );
    }

    #[test]
    fn a_reply_with_a_domain_is_refused() {
        // Сервер шлёт только числовой адрес; имя означает, что на том конце
        // не Snell или не эта его версия.
        assert!(open(&[0x03, b'a']).is_err());
    }

    #[test]
    fn a_reply_cut_short_is_refused() {
        assert!(open(&[]).is_err());
        assert!(open(&[ATYP_IPV4, 1, 2]).is_err());
        assert!(open(&[ATYP_IPV4, 1, 2, 3, 4]).is_err(), "нет порта");
    }

    #[test]
    fn a_name_too_long_to_fit_is_refused() {
        let long = "a".repeat(256);
        assert!(seal(&SocketAddress::domain(&long, 1), &[]).is_err());
    }
}
