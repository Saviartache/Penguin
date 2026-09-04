//! Запись адреса из RFC 1928, §5: тип, хост, порт.
//!
//! ```text
//! +------+----------+----------+
//! | ATYP |   ADDR   |   PORT   |
//! +------+----------+----------+
//! |  1   | 4/16/1+n |    2     |
//! +------+----------+----------+
//! ```
//!
//! Придумана она для SOCKS5, но ею пользуются и те, кто к SOCKS5 отношения не
//! имеет: Trojan повторяет её после пароля, Shadowsocks — в начале
//! зашифрованного потока, Snell и Brook — в своих заголовках. Поэтому она
//! лежит здесь, а не в крейте SOCKS5.

use std::net::IpAddr;

use penguin_core::address::{Address, SocketAddress};

use crate::error::{TransportError, TransportResult};

/// Числовой адрес IPv4.
pub const ATYP_IPV4: u8 = 0x01;
/// Доменное имя.
pub const ATYP_DOMAIN: u8 = 0x03;
/// Числовой адрес IPv6.
pub const ATYP_IPV6: u8 = 0x04;

/// Сколько байт займёт адрес в этой записи.
///
/// Нужен тем, кто пишет длину перед адресом или дополняет запрос до
/// круглого размера, — считать её повторным разбором накладно.
pub fn encoded_len(address: &SocketAddress) -> usize {
    match &address.host {
        Address::Ip(IpAddr::V4(_)) => 1 + 4 + 2,
        Address::Ip(IpAddr::V6(_)) => 1 + 16 + 2,
        Address::Domain(domain) => 1 + 1 + domain.len() + 2,
    }
}

/// Дописывает адрес в буфер.
///
/// `Err` — домен длиннее 255 байт или пустой: его длина пишется одним байтом,
/// и такой адрес в запрос не поместится.
pub fn encode(address: &SocketAddress, out: &mut Vec<u8>) -> TransportResult<()> {
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
            out.push(ATYP_DOMAIN);
            push_domain(domain, out)?;
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
pub fn decode(bytes: &[u8]) -> TransportResult<Option<(SocketAddress, usize)>> {
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

/// Хост по типу и хвосту. Число съеденных байт — без байта типа.
///
/// Свободная функция, потому что тот же разбор нужен записи [`v2ray`], где
/// типы пронумерованы иначе, а хосты те же.
///
/// [`v2ray`]: super::v2ray
pub(crate) fn read_host(atyp: u8, rest: &[u8]) -> TransportResult<Option<(Address, usize)>> {
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
                .map_err(|_| TransportError::malformed("имя в ответе не UTF-8"))?;
            (Address::domain(name), 1 + len)
        }
        other => {
            return Err(TransportError::malformed(format!(
                "неизвестный тип адреса {other:#04x}"
            )));
        }
    };
    Ok(Some(found))
}

/// Дописывает домен: байт длины и байты имени.
pub(crate) fn push_domain(domain: &str, out: &mut Vec<u8>) -> TransportResult<()> {
    let bytes = domain.as_bytes();
    let len = u8::try_from(bytes.len())
        .map_err(|_| TransportError::address(format!("имя длиной {} байт", bytes.len())))?;
    if len == 0 {
        return Err(TransportError::address("пустое имя"));
    }
    out.push(len);
    out.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(address: SocketAddress) {
        let mut out = Vec::new();
        encode(&address, &mut out).expect("собирается");
        assert_eq!(out.len(), encoded_len(&address), "длина посчитана мимо");

        let (back, consumed) = decode(&out).expect("разбирается").expect("целиком");
        assert_eq!(back, address);
        assert_eq!(consumed, out.len(), "съедено не всё");
    }

    #[test]
    fn every_kind_of_address_survives_the_round_trip() {
        round_trip(SocketAddress::ip("203.0.113.5".parse().unwrap(), 443));
        round_trip(SocketAddress::ip("2001:db8::1".parse().unwrap(), 443));
        round_trip(SocketAddress::domain("example.com", 8443));
    }

    #[test]
    fn the_bytes_are_the_ones_the_rfc_names() {
        // Запись проверяется по байтам, а не только круговым прогоном: свой
        // разбор согласится сам с собой при любой ошибке в номерах типов.
        let mut out = Vec::new();
        encode(
            &SocketAddress::ip("203.0.113.5".parse().unwrap(), 443),
            &mut out,
        )
        .unwrap();
        assert_eq!(out, [0x01, 203, 0, 113, 5, 0x01, 0xBB]);

        out.clear();
        encode(&SocketAddress::domain("a.io", 80), &mut out).unwrap();
        assert_eq!(out, [0x03, 4, b'a', b'.', b'i', b'o', 0x00, 0x50]);
    }

    #[test]
    fn a_domain_stays_a_domain() {
        let mut out = Vec::new();
        encode(&SocketAddress::domain("youtube.com", 443), &mut out).unwrap();
        assert_eq!(out[0], ATYP_DOMAIN);
        assert_eq!(out[1], "youtube.com".len() as u8);
    }

    #[test]
    fn a_half_read_header_is_not_an_error() {
        // Заголовок мог прийти не целиком: «неполно» и «сломано» — разные
        // ответы, и путать их значит рвать живое соединение.
        let mut out = Vec::new();
        encode(&SocketAddress::domain("example.com", 443), &mut out).unwrap();

        for cut in 0..out.len() {
            assert!(
                decode(&out[..cut]).expect("не сломано").is_none(),
                "обрезанный до {cut} байт заголовок разобрался целиком"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_left_alone() {
        // За адресом в датаграмме идут данные: съесть их значит потерять
        // первый пакет каждой UDP-сессии.
        let mut out = Vec::new();
        encode(&SocketAddress::domain("example.com", 443), &mut out).unwrap();
        let header = out.len();
        out.extend_from_slice("данные".as_bytes());

        let (_, consumed) = decode(&out).unwrap().unwrap();
        assert_eq!(consumed, header);
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
