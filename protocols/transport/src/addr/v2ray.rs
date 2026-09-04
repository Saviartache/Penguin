//! Запись адреса у VLESS и VMess: порт, тип, хост.
//!
//! ```text
//! +----------+------+----------+
//! |   PORT   | TYPE |   ADDR   |
//! +----------+------+----------+
//! |    2     |  1   | 4/1+n/16 |
//! +----------+------+----------+
//! ```
//!
//! Отличий от [`socks`](super::socks) два, и оба — ловушка:
//!
//! 1. **Порт стоит первым**, а не последним.
//! 2. **Домен — это `2`**, а не `3`. Тройка здесь означает IPv6, то есть
//!    ровно тот номер, под которым в записи SOCKS5 идёт домен.
//!
//! Из-за второго общий кодировщик с флагом однажды записал бы домен как
//! IPv6, а сервер прочитал бы шестнадцать байт имени как адрес и отправил бы
//! запрос неизвестно куда. Поэтому кодировщика два.

use std::net::IpAddr;

use penguin_core::address::{Address, SocketAddress};

use super::socks::{push_domain, read_host};
use crate::error::{TransportError, TransportResult};

/// Числовой адрес IPv4.
pub const TYPE_IPV4: u8 = 0x01;
/// Доменное имя. В записи SOCKS5 под этим номером идёт IPv6.
pub const TYPE_DOMAIN: u8 = 0x02;
/// Числовой адрес IPv6.
pub const TYPE_IPV6: u8 = 0x03;

/// Сколько байт займёт адрес в этой записи.
pub fn encoded_len(address: &SocketAddress) -> usize {
    match &address.host {
        Address::Ip(IpAddr::V4(_)) => 2 + 1 + 4,
        Address::Ip(IpAddr::V6(_)) => 2 + 1 + 16,
        Address::Domain(domain) => 2 + 1 + 1 + domain.len(),
    }
}

/// Дописывает адрес в буфер.
pub fn encode(address: &SocketAddress, out: &mut Vec<u8>) -> TransportResult<()> {
    out.extend_from_slice(&address.port.to_be_bytes());
    match &address.host {
        Address::Ip(IpAddr::V4(ip)) => {
            out.push(TYPE_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            out.push(TYPE_IPV6);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(domain) => {
            out.push(TYPE_DOMAIN);
            push_domain(domain, out)?;
        }
    }
    Ok(())
}

/// Читает адрес с начала среза.
///
/// `Ok(None)` — байт пока не хватает.
pub fn decode(bytes: &[u8]) -> TransportResult<Option<(SocketAddress, usize)>> {
    let Some(port) = bytes.first_chunk::<2>() else {
        return Ok(None);
    };
    let port = u16::from_be_bytes(*port);

    let Some((&kind, rest)) = bytes.get(2..).and_then(<[u8]>::split_first) else {
        return Ok(None);
    };

    // Разбор хоста общий с записью SOCKS5 — различаются только номера, и
    // перевод между ними стоит одной строки. Сам разбор, повторённый дважды,
    // однажды разошёлся бы в мелочи вроде имени не в UTF-8.
    let atyp = match kind {
        TYPE_IPV4 => super::socks::ATYP_IPV4,
        TYPE_DOMAIN => super::socks::ATYP_DOMAIN,
        TYPE_IPV6 => super::socks::ATYP_IPV6,
        other => {
            return Err(TransportError::malformed(format!(
                "неизвестный тип адреса {other:#04x}"
            )));
        }
    };

    let Some((host, consumed)) = read_host(atyp, rest)? else {
        return Ok(None);
    };
    Ok(Some((SocketAddress::new(host, port), 2 + 1 + consumed)))
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
    fn the_port_comes_first_and_a_domain_is_two() {
        // Тот самый тест, ради которого записи разделены: перепутанные
        // номера дали бы имя, прочитанное как IPv6.
        let mut out = Vec::new();
        encode(&SocketAddress::domain("a.io", 443), &mut out).unwrap();
        assert_eq!(out, [0x01, 0xBB, 0x02, 4, b'a', b'.', b'i', b'o']);
    }

    #[test]
    fn the_two_layouts_do_not_read_each_other() {
        // Прямая проверка того, что запись SOCKS5, прочитанная здесь, не
        // выдаёт себя за верную: молчаливое согласие двух записей — самая
        // дорогая ошибка из возможных.
        let address = SocketAddress::domain("example.com", 443);
        let mut socks = Vec::new();
        super::super::socks::encode(&address, &mut socks).unwrap();

        match decode(&socks) {
            Err(_) => {}
            Ok(None) => {}
            Ok(Some((read, _))) => assert_ne!(read, address, "две записи совпали"),
        }
    }

    #[test]
    fn a_half_read_header_is_not_an_error() {
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
        let mut out = Vec::new();
        encode(&SocketAddress::domain("example.com", 443), &mut out).unwrap();
        let header = out.len();
        out.extend_from_slice("данные".as_bytes());

        let (_, consumed) = decode(&out).unwrap().unwrap();
        assert_eq!(consumed, header);
    }

    #[test]
    fn an_unknown_address_type_is_reported() {
        assert!(decode(&[0x01, 0xBB, 0x09, 1, 2, 3, 4]).is_err());
    }
}
