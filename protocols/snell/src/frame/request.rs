//! Заголовок запроса.
//!
//! ```text
//! +--------+---------+-------------+-----------+------+------+
//! | версия | команда | длина имени | имя (0)   | длина| хост | порт
//! |        |         |  клиента    | клиента   | хоста|      |
//! +--------+---------+-------------+-----------+------+------+
//! |   1    |    1    |      1      |    0..n   |  1   | 0..255| 2 (BE)
//! +--------+---------+-------------+-----------+------+------+
//! ```
//!
//! # Две неожиданности
//!
//! **Версия здесь всегда `1`.** Не та, что в настройках: байт версии не
//! менялся с первого выпуска протокола, и пятая версия шлёт в нём ту же
//! единицу. Различаются версии шифром и обрамлением, а не этим байтом.
//!
//! **Хост всегда строка.** Даже числовой адрес: `203.0.113.5` уходит семью
//! символами, а не четырьмя байтами. Двоичной записи адреса у Snell для TCP
//! нет вовсе — она есть только у датаграмм ([`super::udp`]).
//!
//! Имя клиента протокол резервирует под многопользовательский режим; все
//! известные реализации пишут ноль, и мы тоже.

use penguin_core::address::{Address, SocketAddress};

use crate::error::{SnellError, SnellResult};

/// Байт версии в заголовке. Не меняется с первого выпуска.
pub const VERSION: u8 = 0x01;

/// Проверка живости. Мы её не шлём — она здесь ради полноты списка.
pub const CMD_PING: u8 = 0x00;

/// Открыть соединение.
pub const CMD_CONNECT: u8 = 0x01;

/// Открыть соединение на переиспользуемом канале.
pub const CMD_CONNECT_V2: u8 = 0x05;

/// Открыть канал датаграмм.
pub const CMD_UDP: u8 = 0x06;

/// Сколько байт занимает имя клиента. Ноль у всех реализаций.
const CLIENT_ID_LEN: u8 = 0;

/// Собирает заголовок соединения.
///
/// `Err` — имя длиннее 255 байт: его длина пишется одним байтом, и такой
/// адрес в запрос не поместится.
pub fn connect(command: u8, target: &SocketAddress) -> SnellResult<Vec<u8>> {
    // Числовой адрес пишется без скобок, даже IPv6. Наш `Display` их ставит —
    // он выводит адрес для человека, — а сервер читает поле как имя узла и на
    // скобках спотыкается.
    let host = match &target.host {
        Address::Domain(domain) => domain.clone(),
        Address::Ip(ip) => ip.to_string(),
    };
    let host = host.as_bytes();
    let len = u8::try_from(host.len())
        .map_err(|_| SnellError::address(format!("хост длиной {} байт", host.len())))?;
    if len == 0 {
        return Err(SnellError::address("пустой хост"));
    }

    let mut out = Vec::with_capacity(3 + 1 + host.len() + 2);
    out.push(VERSION);
    out.push(command);
    out.push(CLIENT_ID_LEN);
    out.push(len);
    out.extend_from_slice(host);
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(out)
}

/// Собирает заголовок канала датаграмм.
///
/// Адреса в нём нет: он стоит на каждой посылке отдельно.
pub fn udp() -> [u8; 3] {
    [VERSION, CMD_UDP, CLIENT_ID_LEN]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_is_the_shape_the_server_reads() {
        let target = SocketAddress::domain("example.com", 443);
        let header = connect(CMD_CONNECT, &target).expect("собирается");

        assert_eq!(header[0], 1, "версия");
        assert_eq!(header[1], CMD_CONNECT, "команда");
        assert_eq!(header[2], 0, "имя клиента");
        assert_eq!(header[3], 11, "длина хоста");
        assert_eq!(&header[4..15], b"example.com");
        assert_eq!(&header[15..], &443u16.to_be_bytes());
    }

    #[test]
    fn a_numeric_address_goes_out_as_text() {
        // Двоичной записи адреса у Snell для TCP нет: четыре байта здесь
        // означали бы хост из четырёх символов.
        let target = SocketAddress::ip("203.0.113.5".parse().unwrap(), 80);
        let header = connect(CMD_CONNECT, &target).expect("собирается");

        assert_eq!(header[3], "203.0.113.5".len() as u8);
        assert_eq!(&header[4..15], b"203.0.113.5");
    }

    #[test]
    fn an_ipv6_address_goes_out_as_text_too() {
        let target = SocketAddress::ip("2001:db8::1".parse().unwrap(), 443);
        let header = connect(CMD_CONNECT, &target).expect("собирается");
        // Без скобок: сервер читает это поле как имя узла и на них
        // спотыкается, а наш вывод адреса для человека их ставит.
        assert_eq!(&header[4..4 + usize::from(header[3])], b"2001:db8::1");
    }

    #[test]
    fn the_version_byte_is_one_whatever_the_version_of_the_protocol() {
        // Байт версии не менялся с первого выпуска; различаются версии
        // шифром и обрамлением.
        for command in [CMD_CONNECT, CMD_CONNECT_V2] {
            let header = connect(command, &SocketAddress::domain("a.io", 1)).expect("собирается");
            assert_eq!(header[0], 1);
        }
        assert_eq!(udp()[0], 1);
    }

    #[test]
    fn the_reuse_command_differs_from_the_plain_one_by_one_byte() {
        let target = SocketAddress::domain("a.io", 1);
        let plain = connect(CMD_CONNECT, &target).expect("собирается");
        let reuse = connect(CMD_CONNECT_V2, &target).expect("собирается");

        assert_eq!(plain[0], reuse[0]);
        assert_eq!((plain[1], reuse[1]), (1, 5));
        assert_eq!(plain[2..], reuse[2..]);
    }

    #[test]
    fn the_udp_header_carries_no_address() {
        // Он стоит на каждой посылке отдельно: один канал обслуживает
        // сколько угодно адресатов.
        assert_eq!(udp(), [1, 6, 0]);
    }

    #[test]
    fn a_host_too_long_to_fit_is_refused() {
        let long = "a".repeat(256);
        assert!(connect(CMD_CONNECT, &SocketAddress::domain(&long, 1)).is_err());
        assert!(connect(CMD_CONNECT, &SocketAddress::domain(&long[..255], 1)).is_ok());
    }
}
