//! Разбор и сборка DNS-сообщений поверх своего кодека `wire`.

use std::net::IpAddr;

use penguin_proto::random;

pub use crate::wire::RecordType;
use crate::wire::{self, HEADER_LEN, Packet};

use crate::error::{DnsError, DnsResult};

/// О чём спрашивают.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// Имя без завершающей точки, в нижнем регистре.
    pub name: String,
    /// Тип записи.
    pub record_type: RecordType,
    /// Идентификатор запроса — он же в ответе.
    pub id: u16,
}

/// Разбирает запрос; берётся только первый вопрос.
pub fn parse_query(datagram: &[u8]) -> DnsResult<Question> {
    let packet = Packet::parse(datagram)?;
    let (name, record_type) = packet
        .question()?
        .ok_or_else(|| DnsError::Malformed("в запросе нет вопроса".to_owned()))?;
    Ok(Question {
        name,
        record_type,
        id: packet.id(),
    })
}

/// Собирает ответ с адресами; адреса чужого для вопроса семейства пропускаются.
///
/// `ttl` — сколько приложению разрешено помнить ответ.
pub fn build_answer(question: &Question, addresses: &[IpAddr], ttl: u32) -> DnsResult<Vec<u8>> {
    let mut out = Vec::with_capacity(HEADER_LEN + question.name.len() + 6 + addresses.len() * 32);
    wire::write_header(&mut out, question.id, wire::QR | wire::RD | wire::RA, 0);
    wire::write_question(&mut out, &question.name, question.record_type)?;

    let mut count = 0u16;
    for &address in addresses {
        if record_type_of(address) == question.record_type {
            wire::write_address(&mut out, address, ttl);
            count += 1;
        }
    }
    out[6..8].copy_from_slice(&count.to_be_bytes());
    Ok(out)
}

/// Собирает рекурсивный запрос; рекурсия нужна, иначе публичный резолвер
/// ответит отсылкой вместо адреса.
pub fn build_query(host: &str, record_type: RecordType, id: u16) -> DnsResult<Vec<u8>> {
    let mut out = Vec::with_capacity(HEADER_LEN + host.len() + 6);
    wire::write_header(&mut out, id, wire::RD, 0);
    wire::write_question(&mut out, host, record_type)?;
    Ok(out)
}

/// Собирает ответ «такого имени нет».
pub fn build_nxdomain(question: &Question) -> DnsResult<Vec<u8>> {
    let mut out = Vec::with_capacity(HEADER_LEN + question.name.len() + 6);
    let flags = wire::QR | wire::RD | wire::RA | wire::NXDOMAIN;
    wire::write_header(&mut out, question.id, flags, 0);
    wire::write_question(&mut out, &question.name, question.record_type)?;
    Ok(out)
}

/// Достаёт адреса из ответа; `NXDOMAIN` — [`DnsError::NotFound`].
pub fn extract_addresses(datagram: &[u8]) -> DnsResult<Vec<IpAddr>> {
    let packet = Packet::parse(datagram)?;
    if packet.rcode() == wire::NXDOMAIN {
        let name = packet.question().ok().flatten().map(|(name, _)| name);
        return Err(DnsError::NotFound(name.unwrap_or_default()));
    }
    packet.addresses()
}

/// Наименьший TTL в ответе — по нему живёт запись в кэше.
pub fn min_ttl(datagram: &[u8]) -> Option<u32> {
    Packet::parse(datagram).ok()?.min_ttl().ok().flatten()
}

/// Подставляет идентификатор запроса в готовый ответ.
pub fn set_id(response: &mut [u8], id: u16) {
    if let Some(head) = response.first_chunk_mut::<2>() {
        *head = id.to_be_bytes();
    }
}

/// Случайный идентификатор запроса: предсказуемый облегчает подделку ответа.
pub fn random_id() -> u16 {
    u16::from_be_bytes(random::array())
}

/// Тип записи по семейству адреса.
pub const fn record_type_of(address: IpAddr) -> RecordType {
    match address {
        IpAddr::V4(_) => RecordType::A,
        IpAddr::V6(_) => RecordType::AAAA,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    /// Запрос `dig example.com A` с EDNS0 (запись OPT в additional).
    const DIG_QUERY: &[u8] = &[
        0xAB, 0xCD, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, //
        0x07, b'E', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, //
        0x00, 0x01, 0x00, 0x01, //
        0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// Ответ публичного резолвера: example.com A 93.184.216.34, TTL 300.
    const EXAMPLE_ANSWER: &[u8] = &[
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, //
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, //
        0x00, 0x01, 0x00, 0x01, //
        0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, //
        0x5D, 0xB8, 0xD8, 0x22,
    ];

    /// www.example.com: CNAME (TTL 60) -> example.com, затем A 192.0.2.1 (TTL 30).
    const CNAME_ANSWER: &[u8] = &[
        0x00, 0x07, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, //
        0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o',
        b'm', 0x00, 0x00, 0x01, 0x00, 0x01, //
        0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x02, 0xC0, 0x10, //
        0xC0, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x04, 192, 0, 2, 1,
    ];

    /// AAAA 2001:db8::1, TTL 120.
    const AAAA_ANSWER: &[u8] = &[
        0x00, 0x09, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, //
        0x01, b'a', 0x00, 0x00, 0x1C, 0x00, 0x01, //
        0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x10, //
        0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("адрес")
    }

    fn question(name: &str, record_type: RecordType) -> Question {
        Question {
            name: name.to_owned(),
            record_type,
            id: 0x1234,
        }
    }

    #[test]
    fn parses_a_recorded_query_with_edns() {
        let parsed = parse_query(DIG_QUERY).expect("разбирается");
        // Имя нормализуется: сопоставители сравнивают именно такой вид.
        assert_eq!(
            parsed,
            question("example.com", RecordType::A).with_id(0xABCD)
        );
    }

    #[test]
    fn recorded_answer_is_read() {
        assert_eq!(
            extract_addresses(EXAMPLE_ANSWER).expect("разбирается"),
            [ip("93.184.216.34")]
        );
        assert_eq!(min_ttl(EXAMPLE_ANSWER), Some(300));
    }

    #[test]
    fn cname_is_skipped_and_ttl_is_the_minimum() {
        assert_eq!(
            extract_addresses(CNAME_ANSWER).expect("разбирается"),
            [ip("192.0.2.1")]
        );
        assert_eq!(min_ttl(CNAME_ANSWER), Some(30));
    }

    #[test]
    fn recorded_aaaa_is_read() {
        assert_eq!(
            extract_addresses(AAAA_ANSWER).expect("разбирается"),
            [ip("2001:db8::1")]
        );
    }

    #[test]
    fn built_answer_matches_the_recorded_bytes() {
        let built = build_answer(
            &question("example.com", RecordType::A),
            &[ip("93.184.216.34")],
            300,
        )
        .expect("собирается");
        assert_eq!(built, EXAMPLE_ANSWER);
    }

    #[test]
    fn built_query_matches_the_wire_form() {
        let built = build_query("Example.com.", RecordType::AAAA, 0x0102).expect("собирается");
        let mut expected = vec![0x01, 0x02, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        expected.extend_from_slice(b"\x07Example\x03com\x00\x00\x1C\x00\x01");
        assert_eq!(built, expected);
    }

    #[test]
    fn answer_round_trips() {
        let q = question("example.com", RecordType::A);
        let address = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 7));
        let answer = build_answer(&q, &[address], 60).expect("собирается");

        assert_eq!(extract_addresses(&answer).expect("разбирается"), [address]);
        assert_eq!(min_ttl(&answer), Some(60));
        // Ответ разбирается и как запрос: идентификатор и вопрос на месте.
        assert_eq!(parse_query(&answer).expect("вопрос"), q);
    }

    #[test]
    fn mismatched_family_is_skipped() {
        // Адрес IPv6 в записи `A` — ответ, который приложение не разберёт.
        let q = question("example.com", RecordType::A);
        let answer = build_answer(&q, &[IpAddr::V6(Ipv6Addr::LOCALHOST)], 60).expect("собирается");
        assert!(extract_addresses(&answer).expect("разбирается").is_empty());
    }

    #[test]
    fn builds_aaaa_answers() {
        let q = question("example.com", RecordType::AAAA);
        let address = ip("2001:db8::1");
        let answer = build_answer(&q, &[address], 60).expect("собирается");
        assert_eq!(extract_addresses(&answer).expect("разбирается"), [address]);
    }

    #[test]
    fn nxdomain_is_reported_as_not_found() {
        let answer =
            build_nxdomain(&question("nowhere.invalid", RecordType::A)).expect("собирается");
        let Err(DnsError::NotFound(name)) = extract_addresses(&answer) else {
            panic!("ожидался NotFound")
        };
        assert_eq!(name, "nowhere.invalid");
    }

    #[test]
    fn set_id_rewrites_only_the_id() {
        let mut answer = EXAMPLE_ANSWER.to_vec();
        set_id(&mut answer, 0xBEEF);
        assert_eq!(&answer[..2], [0xBE, 0xEF]);
        assert_eq!(&answer[2..], &EXAMPLE_ANSWER[2..]);
        set_id(&mut [], 1);
    }

    #[test]
    fn garbage_is_rejected_not_panicking() {
        assert!(parse_query(&[]).is_err());
        assert!(parse_query(&[0xFF; 64]).is_err());
        assert!(extract_addresses(&[0x00, 0x01]).is_err());
        assert_eq!(min_ttl(&[0xAB; 3]), None);
    }

    #[test]
    fn truncated_answer_is_an_error_at_every_length() {
        for len in 0..EXAMPLE_ANSWER.len() {
            assert!(extract_addresses(&EXAMPLE_ANSWER[..len]).is_err(), "{len}");
        }
        for len in 0..CNAME_ANSWER.len() {
            assert!(extract_addresses(&CNAME_ANSWER[..len]).is_err(), "{len}");
        }
    }

    #[test]
    fn pointer_loop_in_the_question_is_rejected() {
        let mut evil = EXAMPLE_ANSWER[..12].to_vec();
        evil.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        assert!(parse_query(&evil).is_err());
    }

    #[test]
    fn answer_count_beyond_the_data_is_rejected() {
        let mut lying = EXAMPLE_ANSWER.to_vec();
        lying[6..8].copy_from_slice(&1000u16.to_be_bytes());
        assert!(extract_addresses(&lying).is_err());
    }

    #[test]
    fn rdata_length_beyond_the_data_is_rejected() {
        let mut lying = EXAMPLE_ANSWER.to_vec();
        let at = lying.len() - 6;
        lying[at..at + 2].copy_from_slice(&0x00FFu16.to_be_bytes());
        assert!(extract_addresses(&lying).is_err());
    }

    #[test]
    fn record_type_follows_the_address() {
        assert_eq!(
            record_type_of(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            RecordType::A
        );
        assert_eq!(
            record_type_of(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            RecordType::AAAA
        );
    }

    impl Question {
        fn with_id(mut self, id: u16) -> Self {
            self.id = id;
            self
        }
    }
}
