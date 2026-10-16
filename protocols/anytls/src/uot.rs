//! UDP поверх потока: `udp-over-tcp` версии 2.
//!
//! Поток к особому имени [`MAGIC_HOST`] несёт датаграммы с адресами (способ из `sing-box`).
//!
//! Записи адреса две и разные:
//!
//! ```text
//!  заголовок запроса   1 байт «связан ли поток с одним адресатом»
//!                      + адрес по SOCKS5   (1 — IPv4, 3 — домен, 4 — IPv6)
//!  каждая датаграмма   адрес по своей записи (0 — IPv4, 1 — IPv6, 2 — домен)
//!                      + длина (2 байта) + данные
//! ```
//!
//! Так у эталона: заголовок пишет сериализатор SOCKS5, датаграммы — свой.
//! Байт `is_connect` у нас всегда `0` (адресатов много); адрес в заголовке обязателен.

use std::net::IpAddr;

use penguin_core::address::{Address, SocketAddress};
use penguin_transport::addr::socks;

use crate::error::{AnyTlsError, AnyTlsResult};

/// Имя, по которому сервер узнаёт поток с датаграммами.
pub const MAGIC_HOST: &str = "sp.v2.udp-over-tcp.arpa";

/// Порт в адресе такого потока: ноль, как у эталона.
pub const MAGIC_PORT: u16 = 0;

/// Числовой адрес IPv4 в записи датаграмм.
pub const ATYP_IPV4: u8 = 0x00;
/// Числовой адрес IPv6 в записи датаграмм.
pub const ATYP_IPV6: u8 = 0x01;
/// Доменное имя в записи датаграмм.
pub const ATYP_DOMAIN: u8 = 0x02;

/// Наибольшая длина адреса: тип, байт длины, имя и порт.
pub const MAX_ADDRESS: usize = 1 + 1 + 255 + 2;

/// Сколько данных помещается в одну датаграмму (длина в двух байтах).
pub const MAX_PAYLOAD: usize = u16::MAX as usize;

/// Куда открывать поток с датаграммами.
pub fn magic_target() -> SocketAddress {
    SocketAddress::domain(MAGIC_HOST, MAGIC_PORT)
}

/// Заголовок потока датаграмм; `bound` — один адресат (у нас не используется, нужен тестам).
pub fn request(bound: bool, destination: &SocketAddress) -> AnyTlsResult<Vec<u8>> {
    let mut out = vec![u8::from(bound)];
    socks::encode(destination, &mut out)?;
    Ok(out)
}

/// Дописывает адрес в записи датаграмм: тип, хост, порт.
pub fn encode_address(address: &SocketAddress, out: &mut Vec<u8>) -> AnyTlsResult<()> {
    match &address.host {
        Address::Ip(IpAddr::V4(ip)) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(domain) => {
            let bytes = domain.as_bytes();
            let len = u8::try_from(bytes.len())
                .map_err(|_| AnyTlsError::malformed(format!("имя длиной {} байт", bytes.len())))?;
            if len == 0 {
                return Err(AnyTlsError::malformed("пустое имя"));
            }
            out.push(ATYP_DOMAIN);
            out.push(len);
            out.extend_from_slice(bytes);
        }
    }
    out.extend_from_slice(&address.port.to_be_bytes());
    Ok(())
}

/// Сколько байт займёт адрес в записи датаграмм.
pub fn address_len(address: &SocketAddress) -> usize {
    match &address.host {
        Address::Ip(IpAddr::V4(_)) => 1 + 4 + 2,
        Address::Ip(IpAddr::V6(_)) => 1 + 16 + 2,
        Address::Domain(domain) => 1 + 1 + domain.len() + 2,
    }
}

/// Читает адрес с начала среза: адрес и число байт; `Ok(None)` — не хватает данных.
pub fn decode_address(bytes: &[u8]) -> AnyTlsResult<Option<(SocketAddress, usize)>> {
    let Some((&atyp, rest)) = bytes.split_first() else {
        return Ok(None);
    };
    let Some((host, consumed)) = read_host(atyp, rest)? else {
        return Ok(None);
    };
    let Some(port) = bytes.get(1 + consumed..).and_then(<[u8]>::first_chunk::<2>) else {
        return Ok(None);
    };
    Ok(Some((
        SocketAddress::new(host, u16::from_be_bytes(*port)),
        1 + consumed + 2,
    )))
}

/// Хост по типу и хвосту; число байт — без байта типа.
fn read_host(atyp: u8, rest: &[u8]) -> AnyTlsResult<Option<(Address, usize)>> {
    let found = match atyp {
        ATYP_IPV4 => match rest.first_chunk::<4>() {
            Some(octets) => (Address::Ip(IpAddr::from(*octets)), 4),
            None => return Ok(None),
        },
        ATYP_IPV6 => match rest.first_chunk::<16>() {
            Some(octets) => (Address::Ip(IpAddr::from(*octets)), 16),
            None => return Ok(None),
        },
        ATYP_DOMAIN => {
            let Some((&len, tail)) = rest.split_first() else {
                return Ok(None);
            };
            let len = usize::from(len);
            let Some(name) = tail.get(..len) else {
                return Ok(None);
            };
            let name = std::str::from_utf8(name)
                .map_err(|_| AnyTlsError::malformed("имя в датаграмме не UTF-8"))?;
            (Address::domain(name), 1 + len)
        }
        other => {
            return Err(AnyTlsError::malformed(format!(
                "неизвестный тип адреса {other:#04x}"
            )));
        }
    };
    Ok(Some(found))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(address: SocketAddress) {
        let mut out = Vec::new();
        encode_address(&address, &mut out).expect("собирается");
        assert_eq!(out.len(), address_len(&address), "длина посчитана мимо");

        let (back, consumed) = decode_address(&out).expect("разбирается").expect("целиком");
        assert_eq!(back, address);
        assert_eq!(consumed, out.len());
    }

    #[test]
    fn every_kind_of_address_survives_the_round_trip() {
        round_trip(SocketAddress::ip("203.0.113.5".parse().unwrap(), 53));
        round_trip(SocketAddress::ip("2001:db8::1".parse().unwrap(), 53));
        round_trip(SocketAddress::domain("dns.example.com", 53));
    }

    #[test]
    fn the_bytes_are_the_ones_the_reference_writes() {
        let mut out = Vec::new();
        encode_address(
            &SocketAddress::ip("203.0.113.5".parse().unwrap(), 53),
            &mut out,
        )
        .unwrap();
        assert_eq!(out, [0x00, 203, 0, 113, 5, 0x00, 0x35]);

        out.clear();
        encode_address(&SocketAddress::domain("a.io", 53), &mut out).unwrap();
        assert_eq!(out, [0x02, 4, b'a', b'.', b'i', b'o', 0x00, 0x35]);
    }

    #[test]
    fn this_record_is_not_the_socks_one() {
        let address = SocketAddress::ip("203.0.113.5".parse().unwrap(), 53);

        let mut ours = Vec::new();
        encode_address(&address, &mut ours).unwrap();
        let mut theirs = Vec::new();
        socks::encode(&address, &mut theirs).unwrap();

        assert_ne!(ours, theirs, "записи совпали — значит одна из них неверна");
        assert_eq!(ours[0], ATYP_IPV4);
        assert_eq!(theirs[0], socks::ATYP_IPV4);
    }

    #[test]
    fn the_request_header_speaks_socks_and_not_this() {
        let target = SocketAddress::domain("example.com", 53);
        let header = request(false, &target).expect("собирается");

        assert_eq!(header[0], 0, "поток не связан с одним адресатом");
        assert_eq!(header[1], socks::ATYP_DOMAIN);

        let bound = request(true, &target).expect("собирается");
        assert_eq!(bound[0], 1);
    }

    #[test]
    fn a_half_read_address_is_not_an_error() {
        let mut out = Vec::new();
        encode_address(&SocketAddress::domain("example.com", 53), &mut out).unwrap();
        for cut in 0..out.len() {
            assert!(
                decode_address(&out[..cut]).expect("не сломано").is_none(),
                "обрезанный до {cut} байт адрес разобрался целиком"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_left_alone() {
        let mut out = Vec::new();
        encode_address(&SocketAddress::domain("example.com", 53), &mut out).unwrap();
        let header = out.len();
        out.extend_from_slice(&[0, 4, 1, 2, 3, 4]);

        let (_, consumed) = decode_address(&out).unwrap().unwrap();
        assert_eq!(consumed, header);
    }

    #[test]
    fn an_unknown_address_type_is_reported() {
        assert!(decode_address(&[0x09, 1, 2, 3, 4, 0, 53]).is_err());
    }

    #[test]
    fn a_domain_too_long_to_fit_is_refused() {
        let long = "a".repeat(256);
        let mut out = Vec::new();
        assert!(encode_address(&SocketAddress::domain(&long, 53), &mut out).is_err());
    }

    #[test]
    fn the_magic_name_is_the_one_the_server_watches_for() {
        assert_eq!(MAGIC_HOST, "sp.v2.udp-over-tcp.arpa");
        assert_eq!(magic_target().host.as_domain(), Some(MAGIC_HOST));
        assert_eq!(magic_target().port, 0, "выдуманный порт отличает нас");
    }
}
