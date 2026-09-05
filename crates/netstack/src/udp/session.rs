//! Сессия по пятёрке с временем жизни: у UDP нет закрытия.
//!
//! UDP через smoltcp намеренно не идёт. Состояния у него нет, а заводить в
//! стеке сокет на каждую пару «источник — назначение» пришлось бы сотнями:
//! один сокет приложения шлёт куда угодно. Дешевле и честнее разобрать
//! заголовок самим и собрать ответный пакет тоже самим — благо в UDP собирать
//! почти нечего.
//!
//! ```text
//!   пакет из TUN ──► разбор ──► сессия по пятёрке ──► наружу
//!   ответ снаружи ──► сборка пакета ──► в TUN
//! ```

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::{BufMut, BytesMut};

use crate::ip::checksum;

/// Сколько сессия живёт без единой датаграммы.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// Ключ сессии: кто и куда.
///
/// Именно пара, а не только источник: правила маршрутизации зависят от
/// назначения, и складывать разные назначения в одну сессию нельзя.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKey {
    /// Адрес приложения.
    pub source: SocketAddr,
    /// Адрес назначения.
    pub destination: SocketAddr,
}

/// Состояние одной сессии.
#[derive(Debug)]
pub struct Session {
    /// Ключ.
    pub key: SessionKey,
    /// Когда через неё в последний раз что-то прошло.
    pub last_seen: Instant,
}

impl Session {
    /// Заводит сессию.
    pub fn new(key: SessionKey, now: Instant) -> Self {
        Self {
            key,
            last_seen: now,
        }
    }

    /// Отмечает, что через сессию только что прошли данные.
    pub fn touch(&mut self, now: Instant) {
        self.last_seen = now;
    }

    /// Сессия просрочена.
    pub fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.last_seen) >= SESSION_TIMEOUT
    }
}

/// Собирает IP-пакет с датаграммой от `from` к `to`.
///
/// Обе стороны собирают пакеты им: входящая — ответ приложению,
/// исходящая — запрос наружу. Порядок аргументов здесь единственное, что
/// их различает, — перепутать его значит отправить ответ самому себе.
pub fn build_datagram(from: SocketAddr, to: SocketAddr, payload: &[u8]) -> Option<BytesMut> {
    match (from, to) {
        (SocketAddr::V4(from), SocketAddr::V4(to)) => Some(build_v4(from, to, payload)),
        (SocketAddr::V6(from), SocketAddr::V6(to)) => Some(build_v6(from, to, payload)),
        // Разные семейства в одном пакете невыразимы; такое означает ошибку
        // выше по стеку.
        _ => None,
    }
}

fn build_v4(from: std::net::SocketAddrV4, to: std::net::SocketAddrV4, payload: &[u8]) -> BytesMut {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;

    let mut packet = BytesMut::with_capacity(total_len);

    // --- заголовок IPv4 ---
    packet.put_u8(0x45); // версия 4, заголовок 20 байт
    packet.put_u8(0); // тип обслуживания
    packet.put_u16(total_len as u16);
    packet.put_u16(0); // идентификатор: фрагментации нет
    packet.put_u16(0x4000); // не фрагментировать
    packet.put_u8(64); // время жизни
    packet.put_u8(17); // UDP
    packet.put_u16(0); // место под сумму
    packet.put_slice(&from.ip().octets());
    packet.put_slice(&to.ip().octets());

    let header_checksum = checksum::ipv4_header(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    // --- заголовок UDP ---
    let udp_start = packet.len();
    packet.put_u16(from.port());
    packet.put_u16(to.port());
    packet.put_u16(udp_len as u16);
    packet.put_u16(0); // место под сумму
    packet.put_slice(payload);

    let udp_checksum = checksum::udp_v4(*from.ip(), *to.ip(), &packet[udp_start..]);
    packet[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());

    packet
}

fn build_v6(from: std::net::SocketAddrV6, to: std::net::SocketAddrV6, payload: &[u8]) -> BytesMut {
    let udp_len = 8 + payload.len();
    let mut packet = BytesMut::with_capacity(40 + udp_len);

    // --- заголовок IPv6 ---
    packet.put_u32(0x6000_0000); // версия 6, класс и метка нулевые
    packet.put_u16(udp_len as u16);
    packet.put_u8(17); // UDP
    packet.put_u8(64); // предел переходов
    packet.put_slice(&from.ip().octets());
    packet.put_slice(&to.ip().octets());

    // --- заголовок UDP ---
    let udp_start = packet.len();
    packet.put_u16(from.port());
    packet.put_u16(to.port());
    packet.put_u16(udp_len as u16);
    packet.put_u16(0);
    packet.put_slice(payload);

    // В IPv6 сумма обязательна: своей суммы у заголовка нет, и без неё
    // повреждение не обнаружится вовсе.
    let udp_checksum = checksum::udp_v6(*from.ip(), *to.ip(), &packet[udp_start..]);
    packet[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());

    packet
}

#[cfg(test)]
mod tests {
    use crate::ip::parse;

    use super::*;

    fn addr(raw: &str) -> SocketAddr {
        raw.parse().expect("адрес")
    }

    #[test]
    fn built_packet_parses_back() {
        // Собранный нами пакет обязан разбираться нашим же разбором:
        // расхождение здесь означало бы, что система его молча выбросит.
        let packet = build_datagram(addr("8.8.8.8:53"), addr("10.0.0.2:50000"), b"answer")
            .expect("собирается");

        let parsed = parse::parse(&packet).expect("разбирается");
        assert_eq!(parsed.source, addr("8.8.8.8:53"));
        assert_eq!(parsed.destination, addr("10.0.0.2:50000"));
        assert_eq!(parsed.payload, b"answer");
    }

    #[test]
    fn ipv4_header_checksum_is_valid() {
        let packet =
            build_datagram(addr("8.8.8.8:53"), addr("10.0.0.2:50000"), b"x").expect("собирается");
        // Сумма по заголовку вместе с её собственным полем сворачивается в
        // ноль — так её и проверяет система.
        assert_eq!(checksum::finish(checksum::sum(&packet[..20])), 0);
    }

    #[test]
    fn udp_checksum_is_valid() {
        let packet = build_datagram(addr("8.8.8.8:53"), addr("10.0.0.2:50000"), b"payload")
            .expect("собирается");

        let total = checksum::pseudo_v4(
            "8.8.8.8".parse().expect("адрес"),
            "10.0.0.2".parse().expect("адрес"),
            17,
            (packet.len() - 20) as u16,
        ) + checksum::sum(&packet[20..]);
        assert_eq!(checksum::finish(total), 0);
    }

    #[test]
    fn builds_ipv6_too() {
        let packet = build_datagram(addr("[2001:db8::1]:53"), addr("[fd00::2]:50000"), b"answer")
            .expect("собирается");
        let parsed = parse::parse(&packet).expect("разбирается");
        assert!(parsed.source.is_ipv6());
        assert_eq!(parsed.payload, b"answer");
    }

    #[test]
    fn mixed_families_are_refused() {
        // Пакет, у которого отправитель IPv4, а получатель IPv6, невыразим.
        assert!(build_datagram(addr("8.8.8.8:53"), addr("[fd00::2]:50000"), b"x").is_none());
    }

    #[test]
    fn empty_payload_is_valid() {
        let packet =
            build_datagram(addr("8.8.8.8:53"), addr("10.0.0.2:50000"), b"").expect("собирается");
        assert_eq!(parse::parse(&packet).expect("разбирается").payload, b"");
    }

    #[test]
    fn session_expires_by_silence() {
        let now = Instant::now();
        let key = SessionKey {
            source: addr("10.0.0.2:50000"),
            destination: addr("8.8.8.8:53"),
        };
        let mut session = Session::new(key, now);

        assert!(!session.is_expired(now + Duration::from_secs(1)));
        assert!(session.is_expired(now + SESSION_TIMEOUT));

        session.touch(now + SESSION_TIMEOUT);
        assert!(!session.is_expired(now + SESSION_TIMEOUT));
    }

    #[test]
    fn destination_is_part_of_the_key() {
        // Один сокет приложения шлёт куда угодно, и решения по разным
        // назначениям разные.
        let source = addr("10.0.0.2:50000");
        let first = SessionKey {
            source,
            destination: addr("8.8.8.8:53"),
        };
        let second = SessionKey {
            source,
            destination: addr("1.1.1.1:53"),
        };
        assert_ne!(first, second);
    }
}
