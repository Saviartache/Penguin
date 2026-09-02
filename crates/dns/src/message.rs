//! Разбор и сборка DNS-сообщений.
//!
//! Тонкая обёртка над `hickory-proto`: свой разбор DNS писать незачем, но и
//! таскать его типы по всему клиенту не стоит. Здесь остаётся ровно то, что
//! нужно перехвату: узнать, о чём спрашивают, и собрать ответ.

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

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

/// Разбирает запрос.
///
/// Берётся только первый вопрос: запросов с несколькими вопросами в природе
/// не бывает, и обслуживать их незачем.
pub fn parse_query(datagram: &[u8]) -> DnsResult<Question> {
    let message = Message::from_bytes(datagram)
        .map_err(|e| DnsError::Malformed(format!("запрос не разбирается: {e}")))?;

    let question = message
        .queries()
        .first()
        .ok_or_else(|| DnsError::Malformed("в запросе нет вопроса".to_owned()))?;

    Ok(Question {
        name: normalize(&question.name().to_utf8()),
        record_type: question.query_type(),
        id: message.id(),
    })
}

/// Собирает ответ с адресами.
///
/// `ttl` — сколько приложению разрешено помнить ответ. Для подставных
/// адресов он короткий: соответствие живёт минуты, и долгий кэш у приложения
/// пережил бы его.
pub fn build_answer(
    question: &Question,
    addresses: &[std::net::IpAddr],
    ttl: u32,
) -> DnsResult<Vec<u8>> {
    let name = Name::from_utf8(&question.name)
        .map_err(|e| DnsError::Malformed(format!("имя `{}`: {e}", question.name)))?;

    let mut message = Message::new();
    message
        .set_id(question.id)
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .set_recursion_available(true)
        .set_response_code(ResponseCode::NoError);

    let mut query = hickory_proto::op::Query::new();
    query
        .set_name(name.clone())
        .set_query_type(question.record_type)
        .set_query_class(DNSClass::IN);
    message.add_query(query);

    for address in addresses {
        // Тип записи и семейство адреса обязаны совпадать: адрес IPv6 в
        // записи `A` — это ответ, который приложение не разберёт.
        let rdata = match (question.record_type, address) {
            (RecordType::A, std::net::IpAddr::V4(v4)) => RData::A(A(*v4)),
            (RecordType::AAAA, std::net::IpAddr::V6(v6)) => RData::AAAA(AAAA(*v6)),
            _ => continue,
        };
        message.add_answer(Record::from_rdata(name.clone(), ttl, rdata));
    }

    message
        .to_vec()
        .map_err(|e| DnsError::Malformed(format!("ответ не собирается: {e}")))
}

/// Собирает ответ «такого имени нет».
pub fn build_nxdomain(question: &Question) -> DnsResult<Vec<u8>> {
    let name = Name::from_utf8(&question.name)
        .map_err(|e| DnsError::Malformed(format!("имя `{}`: {e}", question.name)))?;

    let mut message = Message::new();
    message
        .set_id(question.id)
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .set_recursion_available(true)
        .set_response_code(ResponseCode::NXDomain);

    let mut query = hickory_proto::op::Query::new();
    query
        .set_name(name)
        .set_query_type(question.record_type)
        .set_query_class(DNSClass::IN);
    message.add_query(query);

    message
        .to_vec()
        .map_err(|e| DnsError::Malformed(format!("ответ не собирается: {e}")))
}

/// Достаёт адреса из ответа.
pub fn extract_addresses(datagram: &[u8]) -> DnsResult<Vec<std::net::IpAddr>> {
    let message = Message::from_bytes(datagram)
        .map_err(|e| DnsError::Malformed(format!("ответ не разбирается: {e}")))?;

    if message.response_code() == ResponseCode::NXDomain {
        return Err(DnsError::NotFound(
            message
                .queries()
                .first()
                .map_or_else(String::new, |q| q.name().to_utf8()),
        ));
    }

    Ok(message
        .answers()
        .iter()
        // `data()` возвращает `Option`: запись без данных законна и
        // встречается в служебных ответах.
        .filter_map(|record| match record.data()? {
            RData::A(A(v4)) => Some(std::net::IpAddr::V4(*v4)),
            RData::AAAA(AAAA(v6)) => Some(std::net::IpAddr::V6(*v6)),
            _ => None,
        })
        .collect())
}

/// Наименьший TTL в ответе — по нему живёт запись в кэше.
pub fn min_ttl(datagram: &[u8]) -> Option<u32> {
    let message = Message::from_bytes(datagram).ok()?;
    message.answers().iter().map(Record::ttl).min()
}

/// Приводит имя к виду, в котором его сравнивают правила.
fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Тип записи по семейству адреса.
pub const fn record_type_of(address: std::net::IpAddr) -> RecordType {
    match address {
        std::net::IpAddr::V4(_) => RecordType::A,
        std::net::IpAddr::V6(_) => RecordType::AAAA,
    }
}

/// Адрес-заглушка IPv4, если ответ пуст.
pub const UNSPECIFIED_V4: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
/// Адрес-заглушка IPv6.
pub const UNSPECIFIED_V6: Ipv6Addr = Ipv6Addr::UNSPECIFIED;

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    fn query_bytes(name: &str, record_type: RecordType) -> Vec<u8> {
        let mut message = Message::new();
        message
            .set_id(0x1234)
            .set_message_type(MessageType::Query)
            .set_recursion_desired(true);

        let mut query = hickory_proto::op::Query::new();
        query
            .set_name(Name::from_utf8(name).expect("имя"))
            .set_query_type(record_type)
            .set_query_class(DNSClass::IN);
        message.add_query(query);
        message.to_vec().expect("собирается")
    }

    #[test]
    fn parses_a_query() {
        let question =
            parse_query(&query_bytes("Example.COM.", RecordType::A)).expect("разбирается");
        // Имя нормализуется: сопоставители сравнивают именно такой вид.
        assert_eq!(question.name, "example.com");
        assert_eq!(question.record_type, RecordType::A);
        assert_eq!(question.id, 0x1234);
    }

    #[test]
    fn answer_round_trips() {
        let question =
            parse_query(&query_bytes("example.com.", RecordType::A)).expect("разбирается");
        let address = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 7));

        let answer = build_answer(&question, &[address], 60).expect("собирается");
        assert_eq!(
            extract_addresses(&answer).expect("разбирается"),
            vec![address]
        );
        assert_eq!(min_ttl(&answer), Some(60));
    }

    #[test]
    fn answer_id_matches_the_query() {
        // Ответ с чужим идентификатором приложение отбросит, и запрос
        // повиснет до тайм-аута.
        let question =
            parse_query(&query_bytes("example.com.", RecordType::A)).expect("разбирается");
        let answer =
            build_answer(&question, &[IpAddr::V4(Ipv4Addr::LOCALHOST)], 60).expect("собирается");

        let parsed = Message::from_bytes(&answer).expect("разбирается");
        assert_eq!(parsed.id(), 0x1234);
        assert_eq!(parsed.message_type(), MessageType::Response);
    }

    #[test]
    fn mismatched_family_is_skipped() {
        // Адрес IPv6 в записи `A` — ответ, который приложение не разберёт.
        let question =
            parse_query(&query_bytes("example.com.", RecordType::A)).expect("разбирается");
        let answer =
            build_answer(&question, &[IpAddr::V6(Ipv6Addr::LOCALHOST)], 60).expect("собирается");
        assert!(extract_addresses(&answer).expect("разбирается").is_empty());
    }

    #[test]
    fn builds_aaaa_answers() {
        let question =
            parse_query(&query_bytes("example.com.", RecordType::AAAA)).expect("разбирается");
        let address = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let answer = build_answer(&question, &[address], 60).expect("собирается");
        assert_eq!(
            extract_addresses(&answer).expect("разбирается"),
            vec![address]
        );
    }

    #[test]
    fn nxdomain_is_reported_as_not_found() {
        // «Имени нет» — законный ответ, который надо запомнить, а не ошибка
        // связи, которую надо повторить.
        let question =
            parse_query(&query_bytes("nowhere.invalid.", RecordType::A)).expect("разбирается");
        let answer = build_nxdomain(&question).expect("собирается");
        assert!(matches!(
            extract_addresses(&answer),
            Err(DnsError::NotFound(_))
        ));
    }

    #[test]
    fn garbage_is_rejected_not_panicking() {
        assert!(parse_query(&[]).is_err());
        assert!(parse_query(&[0xFF; 64]).is_err());
        assert!(extract_addresses(&[0x00, 0x01]).is_err());
        assert_eq!(min_ttl(&[0xAB; 3]), None);
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
}
