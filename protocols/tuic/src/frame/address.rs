//! Запись адреса у TUIC. Третья в проекте, и снова другая.
//!
//! ```text
//! +------+----------+----------+
//! | TYPE |   ADDR   |   PORT   |
//! +------+----------+----------+
//! |  1   | сколько  |    2     |
//! +------+----------+----------+
//! ```
//!
//! | Тип | Что это |
//! |---|---|
//! | `0xff` | адреса нет |
//! | `0x00` | доменное имя, с байтом длины впереди |
//! | `0x01` | IPv4 |
//! | `0x02` | IPv6 |
//!
//! # Почему не взять готовую
//!
//! Их в проекте уже две: `socks` (`1` IPv4, `3` домен, `4` IPv6; порт в конце)
//! и `v2ray` (порт впереди; `1`, `2`, `3`). Здесь третья: порт снова в конце,
//! но домен — это `0`, а IPv6 — `2`, то есть номер, под которым в `v2ray` идёт
//! домен.
//!
//! Свести их в одну с флагом — значит завести место, где перепутанный флаг
//! отправляет имя туда, где ждут шестнадцать байт адреса. Ошибка при этом
//! видна не на сборке и не на тестах кодировщика, а как «сервер молчит».
//!
//! # Пустой адрес — не пустое имя
//!
//! `0xff` означает, что адреса в этом сообщении нет вовсе. Так помечены все
//! куски датаграммы, кроме первого: адрес назван один раз, и повторять его в
//! каждом куске незачем.

use std::net::IpAddr;

use penguin_core::address::{Address, SocketAddress};

use crate::error::{TuicError, TuicResult};

/// Адреса нет.
pub const TYPE_NONE: u8 = 0xff;
/// Доменное имя.
pub const TYPE_DOMAIN: u8 = 0x00;
/// IPv4.
pub const TYPE_IPV4: u8 = 0x01;
/// IPv6.
pub const TYPE_IPV6: u8 = 0x02;

/// Сколько байт займёт адрес.
pub fn encoded_len(address: Option<&SocketAddress>) -> usize {
    match address {
        None => 1,
        Some(address) => match &address.host {
            Address::Ip(IpAddr::V4(_)) => 1 + 4 + 2,
            Address::Ip(IpAddr::V6(_)) => 1 + 16 + 2,
            Address::Domain(domain) => 1 + 1 + domain.len() + 2,
        },
    }
}

/// Дописывает адрес в буфер. `None` — адреса нет.
pub fn encode(address: Option<&SocketAddress>, out: &mut Vec<u8>) -> TuicResult<()> {
    let Some(address) = address else {
        out.push(TYPE_NONE);
        return Ok(());
    };

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
            let bytes = domain.as_bytes();
            let len = u8::try_from(bytes.len())
                .map_err(|_| TuicError::address(format!("имя длиной {} байт", bytes.len())))?;
            if len == 0 {
                return Err(TuicError::address("пустое имя"));
            }
            out.push(TYPE_DOMAIN);
            out.push(len);
            out.extend_from_slice(bytes);
        }
    }
    out.extend_from_slice(&address.port.to_be_bytes());
    Ok(())
}

/// Читает адрес с начала среза.
///
/// Возвращает адрес (или его отсутствие) и число съеденных байт.
/// `Ok(None)` — байт пока не хватает.
#[allow(clippy::type_complexity)]
pub fn decode(bytes: &[u8]) -> TuicResult<Option<(Option<SocketAddress>, usize)>> {
    let Some((&kind, rest)) = bytes.split_first() else {
        return Ok(None);
    };

    if kind == TYPE_NONE {
        return Ok(Some((None, 1)));
    }

    let (host, consumed) = match kind {
        TYPE_IPV4 => match rest.first_chunk::<4>() {
            Some(octets) => (Address::Ip(IpAddr::from(*octets)), 4),
            None => return Ok(None),
        },
        TYPE_IPV6 => match rest.first_chunk::<16>() {
            Some(octets) => (Address::Ip(IpAddr::from(*octets)), 16),
            None => return Ok(None),
        },
        TYPE_DOMAIN => {
            let Some((&len, tail)) = rest.split_first() else {
                return Ok(None);
            };
            let len = usize::from(len);
            let Some(name) = tail.get(..len) else {
                return Ok(None);
            };
            let name =
                std::str::from_utf8(name).map_err(|_| TuicError::malformed("имя не UTF-8"))?;
            (Address::domain(name), 1 + len)
        }
        other => {
            return Err(TuicError::malformed(format!(
                "неизвестный тип адреса {other:#04x}"
            )));
        }
    };

    let Some(port) = bytes.get(1 + consumed..).and_then(<[u8]>::first_chunk::<2>) else {
        return Ok(None);
    };
    Ok(Some((
        Some(SocketAddress::new(host, u16::from_be_bytes(*port))),
        1 + consumed + 2,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(address: SocketAddress) {
        let mut out = Vec::new();
        encode(Some(&address), &mut out).expect("собирается");
        assert_eq!(
            out.len(),
            encoded_len(Some(&address)),
            "длина посчитана мимо"
        );

        let (back, used) = decode(&out).expect("разбирается").expect("целиком");
        assert_eq!(back.as_ref(), Some(&address));
        assert_eq!(used, out.len(), "съедено не всё");
    }

    #[test]
    fn every_kind_of_address_survives_the_round_trip() {
        round_trip(SocketAddress::ip("203.0.113.5".parse().unwrap(), 443));
        round_trip(SocketAddress::ip("2001:db8::1".parse().unwrap(), 443));
        round_trip(SocketAddress::domain("example.com", 8443));
    }

    #[test]
    fn the_numbers_are_the_ones_the_spec_names() {
        // Третья запись адреса в проекте, и все три расходятся. Проверять
        // круговым прогоном мало: он согласится сам с собой при любой ошибке
        // в номерах.
        let mut out = Vec::new();
        encode(Some(&SocketAddress::domain("a.io", 443)), &mut out).unwrap();
        assert_eq!(out, [0x00, 4, b'a', b'.', b'i', b'o', 0x01, 0xBB]);

        out.clear();
        encode(
            Some(&SocketAddress::ip("203.0.113.5".parse().unwrap(), 443)),
            &mut out,
        )
        .unwrap();
        assert_eq!(out, [0x01, 203, 0, 113, 5, 0x01, 0xBB]);

        out.clear();
        encode(
            Some(&SocketAddress::ip("2001:db8::1".parse().unwrap(), 80)),
            &mut out,
        )
        .unwrap();
        assert_eq!(out[0], 0x02);
        assert_eq!(&out[17..], &[0x00, 0x50]);
    }

    #[test]
    fn the_three_layouts_of_the_project_do_not_agree() {
        // Прямая проверка того, ради чего кодировщиков три. Одно и то же имя
        // в трёх записях обязано дать три разные строки байт: сведи их в одну
        // с флагом — и перепутанный флаг отправит имя туда, где ждут адрес.
        let address = SocketAddress::domain("example.com", 443);

        let mut here = Vec::new();
        encode(Some(&address), &mut here).unwrap();
        let mut socks = Vec::new();
        penguin_transport::addr::socks::encode(&address, &mut socks).unwrap();
        let mut v2ray = Vec::new();
        penguin_transport::addr::v2ray::encode(&address, &mut v2ray).unwrap();

        assert_ne!(here, socks);
        assert_ne!(here, v2ray);
        assert_ne!(socks, v2ray);
    }

    #[test]
    fn no_address_is_a_single_byte() {
        // Так помечены все куски датаграммы, кроме первого: адрес назван один
        // раз, и повторять его незачем.
        let mut out = Vec::new();
        encode(None, &mut out).expect("собирается");
        assert_eq!(out, [TYPE_NONE]);
        assert_eq!(encoded_len(None), 1);

        let (back, used) = decode(&out).expect("разбирается").expect("целиком");
        assert!(back.is_none());
        assert_eq!(used, 1);
    }

    #[test]
    fn a_half_read_address_is_not_an_error() {
        let mut out = Vec::new();
        encode(Some(&SocketAddress::domain("example.com", 443)), &mut out).unwrap();

        for cut in 0..out.len() {
            assert!(
                decode(&out[..cut]).expect("не сломано").is_none(),
                "обрезанный до {cut} байт адрес разобрался целиком"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_left_alone() {
        // За адресом в команде идут данные: съесть их значит потерять начало
        // каждой датаграммы.
        let mut out = Vec::new();
        encode(Some(&SocketAddress::domain("example.com", 443)), &mut out).unwrap();
        let header = out.len();
        out.extend_from_slice("данные".as_bytes());

        let (_, used) = decode(&out).unwrap().unwrap();
        assert_eq!(used, header);
    }

    #[test]
    fn an_unknown_address_type_is_reported() {
        assert!(decode(&[0x09, 1, 2, 3, 4, 0, 80]).is_err());
    }

    #[test]
    fn a_domain_too_long_to_fit_is_refused() {
        let long = "a".repeat(256);
        let mut out = Vec::new();
        assert!(encode(Some(&SocketAddress::domain(&long, 443)), &mut out).is_err());
    }
}
