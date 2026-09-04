//! Заголовок запроса: байт сети и адрес назначения.
//!
//! ```text
//! +------+----------------------------+
//! | сеть |      адрес по SOCKS5       |
//! +------+----------------------------+
//! |  1   | тип(1) + хост + порт(2 BE) |
//! +------+----------------------------+
//! ```
//!
//! # Про запись адреса
//!
//! В спецификации Juicity написано, что типы адреса пронумерованы `0`, `1`,
//! `2`. **Это не так.** И клиент, и сервер эталона берут запись из общего с
//! Trojan модуля, то есть пользуются нумерацией SOCKS5: `1` — IPv4, `3` —
//! домен, `4` — IPv6. Реализация по документу не поняла бы ни один живой
//! сервер, а найти это можно было бы только по молчанию в поле.
//!
//! Поэтому адрес пишет [`penguin_transport::addr::socks`], и своей записи у
//! этого протокола нет вовсе.

use penguin_core::address::SocketAddress;
use penguin_transport::addr::socks;

use crate::error::JuicityResult;

/// Поток несёт соединение TCP.
pub const NET_TCP: u8 = 0x01;

/// Поток несёт датаграммы UDP.
pub const NET_UDP: u8 = 0x03;

/// Собирает заголовок запроса.
pub fn header(network: u8, target: &SocketAddress) -> JuicityResult<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + socks::encoded_len(target));
    out.push(network);
    socks::encode(target, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use penguin_transport::addr::socks::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};

    use super::*;

    #[test]
    fn the_header_is_the_network_byte_and_a_socks_address() {
        let target = SocketAddress::ip("203.0.113.5".parse().unwrap(), 443);
        let header = header(NET_TCP, &target).expect("собирается");
        assert_eq!(header, [NET_TCP, ATYP_IPV4, 203, 0, 113, 5, 0x01, 0xBB]);
    }

    #[test]
    fn a_domain_stays_a_domain() {
        let header =
            header(NET_TCP, &SocketAddress::domain("example.com", 443)).expect("собирается");
        assert_eq!(header[0], NET_TCP);
        assert_eq!(header[1], ATYP_DOMAIN);
        assert_eq!(header[2], "example.com".len() as u8);
    }

    #[test]
    fn the_address_types_are_the_socks_ones_and_not_the_ones_the_spec_names() {
        // Спецификация Juicity называет `0`, `1`, `2`. Эталон пишет `1`, `3`,
        // `4`. Тест стоит на стороне эталона нарочно: по документу клиент не
        // понял бы ни один живой сервер.
        assert_eq!(ATYP_IPV4, 1);
        assert_eq!(ATYP_DOMAIN, 3);
        assert_eq!(ATYP_IPV6, 4);

        let v6 = header(
            NET_TCP,
            &SocketAddress::ip("2001:db8::1".parse().unwrap(), 1),
        )
        .unwrap();
        assert_eq!(v6[1], ATYP_IPV6);
    }

    #[test]
    fn udp_and_tcp_differ_by_one_byte_and_that_byte_is_first() {
        let target = SocketAddress::domain("a.io", 53);
        let tcp = header(NET_TCP, &target).expect("собирается");
        let udp = header(NET_UDP, &target).expect("собирается");
        assert_eq!(tcp[1..], udp[1..]);
        assert_eq!((tcp[0], udp[0]), (1, 3));
    }

    #[test]
    fn a_domain_too_long_to_fit_is_refused() {
        let long = "a".repeat(256);
        assert!(header(NET_TCP, &SocketAddress::domain(&long, 443)).is_err());
    }
}
