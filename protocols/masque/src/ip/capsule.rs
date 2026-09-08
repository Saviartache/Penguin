//! Капсулы согласования адреса и маршрута `CONNECT-IP` (RFC 9484, §4.7).
//!
//! Три капсулы, общий скелет `Type`/`Length`/`Value` из [`crate::capsule`],
//! своё содержимое:
//!
//! ```text
//!  Assigned Address / Requested Address {
//!    Request ID (varint),
//!    IP Version (8),          // 4 или 6
//!    IP Address (32 или 128), // длина по версии
//!    IP Prefix Length (8),
//!  }
//!
//!  IP Address Range {
//!    IP Version (8),
//!    Start IP Address (32 или 128),
//!    End IP Address (32 или 128),
//!    IP Protocol (8),
//!  }
//! ```
//!
//! Отдельных тестовых векторов для этих капсул RFC не даёт (в отличие от
//! варинта, RFC 9000 §16) — сверка ниже по формату из текста RFC и обратным
//! проходом кодирование-разбор, так же, как у капсулы `DATAGRAM` в
//! [`crate::capsule`].
//!
//! `ADDRESS_ASSIGN` и `ROUTE_ADVERTISEMENT` этот клиент только читает: он не
//! ассоциирует адреса и не объявляет маршруты собеседнику (сетевое-к-сетевому
//! пиринг, RFC 9484 §1, здесь не поддержан — клиент только удалённого
//! доступа). Поэтому сборщики для них — `#[cfg(test)]`: у настоящего кода
//! нет причины их звать, а тестам нужны байты для проверки разбора.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::capsule::encode_capsule;
use crate::error::MasqueError;
use crate::varint;

/// Тип капсулы `ADDRESS_ASSIGN` (RFC 9484, §4.7.1).
pub(super) const CAPSULE_TYPE_ADDRESS_ASSIGN: u64 = 0x01;
/// Тип капсулы `ADDRESS_REQUEST` (RFC 9484, §4.7.2).
pub(super) const CAPSULE_TYPE_ADDRESS_REQUEST: u64 = 0x02;
/// Тип капсулы `ROUTE_ADVERTISEMENT` (RFC 9484, §4.7.3).
pub(super) const CAPSULE_TYPE_ROUTE_ADVERTISEMENT: u64 = 0x03;

/// Context ID полезной нагрузки IP-пакета (RFC 9484, §5) — то же
/// зарезервированное значение `0`, что и у CONNECT-UDP ([`crate::capsule::CONTEXT_ID_UDP`]),
/// но в пространстве имён потока `CONNECT-IP`, своём для каждого запроса.
pub(super) const CONTEXT_ID_IP: u64 = 0;

const IP_VERSION_4: u8 = 4;
const IP_VERSION_6: u8 = 6;

/// Один назначенный сервером адрес (RFC 9484, Figure 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AssignedAddress {
    /// Идентификатор запроса, которому соответствует назначение; `0` — адрес
    /// выдан без запроса.
    pub request_id: u64,
    /// Назначенный адрес.
    pub address: IpAddr,
    /// Длина префикса, в пределах которого можно указывать адрес источника.
    pub prefix_len: u8,
}

/// Один запрошенный клиентом адрес (RFC 9484, Figure 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RequestedAddress {
    /// Идентификатор запроса: свой у каждого, не равен нулю.
    pub request_id: u64,
    /// Предпочитаемый адрес; несконкретный (`0.0.0.0`/`::`) — предпочтения нет.
    pub address: IpAddr,
    /// Предпочитаемая длина префикса.
    pub prefix_len: u8,
}

/// Один диапазон маршрута (RFC 9484, Figure 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AddressRange {
    /// Начало диапазона включительно.
    pub start: IpAddr,
    /// Конец диапазона включительно.
    pub end: IpAddr,
    /// Номер протокола IP, которому разрешён этот диапазон; `0` — любой.
    pub ip_protocol: u8,
}

fn ip_version(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => IP_VERSION_4,
        IpAddr::V6(_) => IP_VERSION_6,
    }
}

fn put_address(buf: &mut BytesMut, addr: IpAddr) {
    match addr {
        IpAddr::V4(v4) => buf.put_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.put_slice(&v6.octets()),
    }
}

fn truncated() -> MasqueError {
    MasqueError::malformed("капсула CONNECT-IP короче заявленной длины")
}

fn take_address(buf: &mut Bytes, version: u8) -> Result<IpAddr, MasqueError> {
    match version {
        IP_VERSION_4 => {
            if buf.remaining() < 4 {
                return Err(truncated());
            }
            let mut octets = [0u8; 4];
            buf.copy_to_slice(&mut octets);
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        IP_VERSION_6 => {
            if buf.remaining() < 16 {
                return Err(truncated());
            }
            let mut octets = [0u8; 16];
            buf.copy_to_slice(&mut octets);
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        other => Err(MasqueError::malformed(format!(
            "неизвестная версия IP в капсуле CONNECT-IP: {other}"
        ))),
    }
}

fn take_u8(buf: &mut Bytes) -> Result<u8, MasqueError> {
    if !buf.has_remaining() {
        return Err(truncated());
    }
    Ok(buf.get_u8())
}

fn take_request_id(buf: &mut Bytes) -> Result<u64, MasqueError> {
    varint::decode_prefix(buf).ok_or_else(truncated)
}

/// Собирает `ADDRESS_REQUEST`: клиент шлёт её, чтобы узнать свой адрес
/// (RFC 9484, §4.7.2) — единственная из трёх капсул этого модуля, которую
/// клиент отправляет по-настоящему (см. [`crate::ip::negotiate`]).
pub(super) fn encode_address_request(addresses: &[RequestedAddress]) -> Bytes {
    let mut value = BytesMut::new();
    for a in addresses {
        varint::encode(a.request_id, &mut value);
        value.put_u8(ip_version(a.address));
        put_address(&mut value, a.address);
        value.put_u8(a.prefix_len);
    }
    encode_capsule(CAPSULE_TYPE_ADDRESS_REQUEST, &value)
}

/// Разбирает значение капсулы `ADDRESS_ASSIGN` (без заголовка `Type`/`Length`).
pub(super) fn decode_address_assign(mut value: Bytes) -> Result<Vec<AssignedAddress>, MasqueError> {
    let mut out = Vec::new();
    while value.has_remaining() {
        let request_id = take_request_id(&mut value)?;
        let version = take_u8(&mut value)?;
        let address = take_address(&mut value, version)?;
        let prefix_len = take_u8(&mut value)?;
        out.push(AssignedAddress {
            request_id,
            address,
            prefix_len,
        });
    }
    Ok(out)
}

/// Разбирает значение капсулы `ADDRESS_REQUEST`.
///
/// Клиент этот разбор зовёт не на своём запросе, а на чужом: сервер вправе
/// сам прислать `ADDRESS_REQUEST`, ожидая, что клиент назначит адрес ему
/// (сетевое-к-сетевому пиринг, RFC 9484 §1) — здесь это не поддержано, и
/// разбор нужен только затем, чтобы назвать в журнале, сколько адресов
/// попросили, а не молчать (см. [`crate::ip::outbound`]).
pub(super) fn decode_address_request(
    mut value: Bytes,
) -> Result<Vec<RequestedAddress>, MasqueError> {
    let mut out = Vec::new();
    while value.has_remaining() {
        let request_id = take_request_id(&mut value)?;
        let version = take_u8(&mut value)?;
        let address = take_address(&mut value, version)?;
        let prefix_len = take_u8(&mut value)?;
        out.push(RequestedAddress {
            request_id,
            address,
            prefix_len,
        });
    }
    Ok(out)
}

/// Разбирает значение капсулы `ROUTE_ADVERTISEMENT`.
pub(super) fn decode_route_advertisement(
    mut value: Bytes,
) -> Result<Vec<AddressRange>, MasqueError> {
    let mut out = Vec::new();
    while value.has_remaining() {
        let version = take_u8(&mut value)?;
        let start = take_address(&mut value, version)?;
        let end = take_address(&mut value, version)?;
        let ip_protocol = take_u8(&mut value)?;
        out.push(AddressRange {
            start,
            end,
            ip_protocol,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Собирает `ADDRESS_ASSIGN` — тестовый двойник, симметричный
    /// [`decode_address_assign`]. У настоящего кода нет причины назначать
    /// адреса серверу (см. документ модуля), но круговой проход по-прежнему
    /// проверяет, что разбор понимает именно тот формат, что описан в RFC.
    fn encode_address_assign_for_test(addresses: &[AssignedAddress]) -> Bytes {
        let mut value = BytesMut::new();
        for a in addresses {
            varint::encode(a.request_id, &mut value);
            value.put_u8(ip_version(a.address));
            put_address(&mut value, a.address);
            value.put_u8(a.prefix_len);
        }
        encode_capsule(CAPSULE_TYPE_ADDRESS_ASSIGN, &value)
    }

    /// Собирает `ROUTE_ADVERTISEMENT` — тестовый двойник, симметричный
    /// [`decode_route_advertisement`]; см. `encode_address_assign_for_test`.
    fn encode_route_advertisement_for_test(ranges: &[AddressRange]) -> Bytes {
        let mut value = BytesMut::new();
        for r in ranges {
            value.put_u8(ip_version(r.start));
            put_address(&mut value, r.start);
            put_address(&mut value, r.end);
            value.put_u8(r.ip_protocol);
        }
        encode_capsule(CAPSULE_TYPE_ROUTE_ADVERTISEMENT, &value)
    }

    /// Отделяет `Value` от заголовка `Type`/`Length` для тестов разбора:
    /// сами `decode_*` работают уже над значением, без заголовка капсулы.
    fn value_of(capsule: Bytes) -> Bytes {
        let mut reader = crate::capsule::CapsuleReader::new();
        reader.push(capsule);
        let (capsule_type, value) = reader
            .next_capsule()
            .expect("разбирается")
            .expect("капсула целиком пришла");
        assert!(
            capsule_type == CAPSULE_TYPE_ADDRESS_ASSIGN
                || capsule_type == CAPSULE_TYPE_ADDRESS_REQUEST
                || capsule_type == CAPSULE_TYPE_ROUTE_ADVERTISEMENT
        );
        value
    }

    #[test]
    fn address_assign_round_trips_ipv4_and_ipv6() {
        let addresses = [
            AssignedAddress {
                request_id: 1,
                address: "203.0.113.9".parse().expect("адрес"),
                prefix_len: 32,
            },
            AssignedAddress {
                request_id: 0,
                address: "2001:db8::9".parse().expect("адрес"),
                prefix_len: 128,
            },
        ];
        let capsule = encode_address_assign_for_test(&addresses);
        let decoded = decode_address_assign(value_of(capsule)).expect("разбирается");
        assert_eq!(decoded, addresses);
    }

    #[test]
    fn a_rejected_request_is_the_all_zero_max_prefix_pattern() {
        // RFC 9484 §4.7.2: отказ — это 0.0.0.0/32 (или ::/128), а не ошибка.
        let rejected = AssignedAddress {
            request_id: 7,
            address: "0.0.0.0".parse().expect("адрес"),
            prefix_len: 32,
        };
        let capsule = encode_address_assign_for_test(&[rejected]);
        let decoded = decode_address_assign(value_of(capsule)).expect("разбирается");
        assert_eq!(decoded, vec![rejected]);
    }

    #[test]
    fn address_request_round_trips() {
        let addresses = [RequestedAddress {
            request_id: 1,
            address: "0.0.0.0".parse().expect("адрес"),
            prefix_len: 32,
        }];
        let capsule = encode_address_request(&addresses);
        let decoded = decode_address_request(value_of(capsule)).expect("разбирается");
        assert_eq!(decoded, addresses);
    }

    #[test]
    fn route_advertisement_round_trips_a_range() {
        let ranges = [AddressRange {
            start: "10.0.0.0".parse().expect("адрес"),
            end: "10.0.0.255".parse().expect("адрес"),
            ip_protocol: 0,
        }];
        let capsule = encode_route_advertisement_for_test(&ranges);
        let decoded = decode_route_advertisement(value_of(capsule)).expect("разбирается");
        assert_eq!(decoded, ranges);
    }

    #[test]
    fn an_unknown_ip_version_is_reported_not_guessed() {
        // Version = 5: RFC требует ровно 4 или 6, третьего не дано.
        let mut value = BytesMut::new();
        varint::encode(1, &mut value); // request id
        value.put_u8(5); // версия
        let err = decode_address_assign(value.freeze()).expect_err("версия неизвестна");
        assert!(err.to_string().contains("5"), "{err}");
    }

    #[test]
    fn a_truncated_capsule_is_reported_not_panicked_on() {
        let mut value = BytesMut::new();
        varint::encode(1, &mut value);
        value.put_u8(IP_VERSION_4);
        value.put_slice(&[1, 2]); // адрес оборван на середине
        assert!(decode_address_assign(value.freeze()).is_err());
    }
}
