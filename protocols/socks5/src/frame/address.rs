//! Адрес в записи SOCKS5: тип, хост, порт (RFC 1928, §5).
//!
//! ```text
//! +------+----------+----------+
//! | ATYP |   ADDR   |   PORT   |
//! +------+----------+----------+
//! |  1   | 4/16/1+n |    2     |
//! +------+----------+----------+
//! ```
//!
//! Домен передаётся доменом, а не разрешается заранее. Это не мелочь: правило
//! «youtube.com в тоннель» имеет смысл ровно до тех пор, пока имя ещё известно,
//! а после разрешения от него остаётся адрес из CDN, общий с десятком других
//! сайтов.

use std::net::IpAddr;

use penguin_core::address::{Address, SocketAddress};

use crate::error::{Socks5Error, Socks5Result};

/// Числовой адрес IPv4.
pub const ATYP_IPV4: u8 = 0x01;
/// Доменное имя.
pub const ATYP_DOMAIN: u8 = 0x03;
/// Числовой адрес IPv6.
pub const ATYP_IPV6: u8 = 0x04;

/// Дописывает адрес в буфер.
///
/// `Err` — домен длиннее 255 байт: его длина пишется одним байтом, и такой
/// адрес в запрос не поместится.
pub fn encode(address: &SocketAddress, out: &mut Vec<u8>) -> Socks5Result<()> {
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
                .map_err(|_| Socks5Error::Address(format!("имя длиной {} байт", bytes.len())))?;
            if len == 0 {
                return Err(Socks5Error::Address("пустое имя".to_owned()));
            }
            out.push(ATYP_DOMAIN);
            out.push(len);
            out.extend_from_slice(bytes);
        }
    }
    out.extend_from_slice(&address.port.to_be_bytes());
    Ok(())
}

/// Читает адрес с начала среза.
///
/// Возвращает адрес и число съеденных байт: за адресом в датаграмме идут
/// данные, и звать длину заново пришлось бы тем же разбором.
///
/// `Ok(None)` — байт пока не хватает. Это не ошибка: заголовок мог прийти не
/// целиком, и отличать «неполно» от «сломано» обязан тот, кто читает.
pub fn decode(bytes: &[u8]) -> Socks5Result<Option<(SocketAddress, usize)>> {
    let Some((&atyp, rest)) = bytes.split_first() else {
        return Ok(None);
    };

    let (host, consumed) = match atyp {
        ATYP_IPV4 => match rest.first_chunk::<4>() {
            Some(octets) => (Address::Ip(IpAddr::from(*octets)), 1 + 4),
            None => return Ok(None),
        },
        ATYP_IPV6 => match rest.first_chunk::<16>() {
            Some(octets) => (Address::Ip(IpAddr::from(*octets)), 1 + 16),
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
                .map_err(|_| Socks5Error::malformed("имя в ответе не UTF-8"))?;
            (Address::domain(name), 1 + 1 + len)
        }
        other => {
            return Err(Socks5Error::malformed(format!(
                "неизвестный тип адреса {other:#04x}"
            )));
        }
    };

    let Some(port) = bytes.get(consumed..).and_then(<[u8]>::first_chunk::<2>) else {
        return Ok(None);
    };
    Ok(Some((
        SocketAddress::new(host, u16::from_be_bytes(*port)),
        consumed + 2,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(address: SocketAddress) {
        let mut out = Vec::new();
        encode(&address, &mut out).expect("собирается");
        let (back, consumed) = decode(&out).expect("разбирается").expect("целиком");
        assert_eq!(back, address);
        assert_eq!(consumed, out.len(), "съедено не всё");
    }

    #[test]
    fn every_kind_of_address_survives_the_round_trip() {
        round_trip(SocketAddress::ip(
            "203.0.113.5".parse().expect("адрес"),
            443,
        ));
        round_trip(SocketAddress::ip(
            "2001:db8::1".parse().expect("адрес"),
            443,
        ));
        round_trip(SocketAddress::domain("example.com", 8443));
    }

    #[test]
    fn a_domain_stays_a_domain() {
        // Разрешить его здесь значило бы потерять имя ровно там, где оно
        // единственное, что есть: правило «youtube.com в тоннель» работает
        // только по имени.
        let mut out = Vec::new();
        encode(&SocketAddress::domain("youtube.com", 443), &mut out).expect("собирается");
        assert_eq!(out[0], ATYP_DOMAIN);
        assert_eq!(out[1], "youtube.com".len() as u8);
    }

    #[test]
    fn a_half_read_header_is_not_an_error() {
        // Заголовок мог прийти не целиком: «неполно» и «сломано» — разные
        // ответы, и путать их значит рвать живое соединение.
        let mut out = Vec::new();
        encode(&SocketAddress::domain("example.com", 443), &mut out).expect("собирается");

        for cut in 0..out.len() {
            assert!(
                decode(&out[..cut]).expect("не сломано").is_none(),
                "обрезанный до {cut} байт заголовок разобрался целиком"
            );
        }
    }

    #[test]
    fn an_unknown_address_type_is_reported() {
        assert!(decode(&[0x07, 1, 2, 3, 4, 0, 80]).is_err());
    }

    #[test]
    fn a_domain_too_long_to_fit_is_refused() {
        // Длина пишется одним байтом: то, что длиннее, молча обрезалось бы в
        // другое имя.
        let long = "a".repeat(256);
        let mut out = Vec::new();
        assert!(encode(&SocketAddress::domain(&long, 443), &mut out).is_err());
    }
}
