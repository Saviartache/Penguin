//! Согласование адреса интерфейса: капсулы `ADDRESS_REQUEST`/`ADDRESS_ASSIGN`
//! (RFC 9484, §4.7.1—4.7.2) сразу после успешного апгрейда.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use penguin_proto::packet::PacketInterface;
use penguin_transport::deadline;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::capsule::{
    self, CAPSULE_TYPE_ADDRESS_ASSIGN, CAPSULE_TYPE_ADDRESS_REQUEST,
    CAPSULE_TYPE_ROUTE_ADVERTISEMENT, RequestedAddress,
};
use super::outbound::INTERFACE_MTU;
use crate::capsule::CapsuleReader;
use crate::error::{MasqueError, MasqueResult};

/// Идентификаторы собственных запросов адреса.
///
/// Значения не значат ничего для сервера, кроме того, что они не равны нулю
/// и не повторяются внутри одного потока (RFC 9484, §4.7.2) — единственное
/// требование к Request ID.
const REQUEST_ID_IPV4: u64 = 1;
const REQUEST_ID_IPV6: u64 = 2;

/// Наибольшая длина одного куска, читаемого из сети за раз.
const READ_CHUNK: usize = 4096;

/// Запрашивает адрес у сервера и ждёт `ADDRESS_ASSIGN`.
///
/// `reader` может уже что-то содержать (хвост, пришедший вместе с ответом на
/// апгрейд) — то, что он накопит сверх `ADDRESS_ASSIGN` (маршруты, а то и
/// первый IP-пакет), не теряется: тот же `reader` передаётся дальше в
/// фоновую задачу разбора как есть.
pub(super) async fn assign_interface<S>(
    io: &mut S,
    reader: &mut CapsuleReader,
) -> MasqueResult<PacketInterface>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = capsule::encode_address_request(&[
        RequestedAddress {
            request_id: REQUEST_ID_IPV4,
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_len: 32,
        },
        RequestedAddress {
            request_id: REQUEST_ID_IPV6,
            address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            prefix_len: 128,
        },
    ]);

    deadline::handshake("согласование адреса CONNECT-IP", async {
        io.write_all(&request).await?;
        io.flush().await?;

        let mut chunk = [0u8; READ_CHUNK];
        loop {
            if let Some(interface) = process_one(reader)? {
                return Ok(interface);
            }

            let read = io.read(&mut chunk).await?;
            if read == 0 {
                return Err(MasqueError::Disconnected(
                    "сервер закрыл поток CONNECT-IP до ADDRESS_ASSIGN".to_owned(),
                ));
            }
            reader.push(Bytes::copy_from_slice(&chunk[..read]));
        }
    })
    .await
}

/// Разбирает и обрабатывает уже накопленные капсулы, пока не дойдёт до
/// `ADDRESS_ASSIGN` или пока не кончатся данные.
fn process_one(reader: &mut CapsuleReader) -> MasqueResult<Option<PacketInterface>> {
    loop {
        let Some((capsule_type, value)) = reader.next_capsule()? else {
            return Ok(None);
        };

        match capsule_type {
            CAPSULE_TYPE_ADDRESS_ASSIGN => {
                let entries = capsule::decode_address_assign(value)?;
                return Ok(Some(interface_from(entries)?));
            }
            CAPSULE_TYPE_ROUTE_ADVERTISEMENT => {
                let ranges = capsule::decode_route_advertisement(value)?;
                tracing::debug!(
                    count = ranges.len(),
                    "сервер объявил маршруты CONNECT-IP до согласования адреса"
                );
            }
            CAPSULE_TYPE_ADDRESS_REQUEST => {
                let requested = capsule::decode_address_request(value)?;
                tracing::warn!(
                    count = requested.len(),
                    "сервер запросил у клиента адрес(а) через ADDRESS_REQUEST — сетевое-к-сетевому \
                     назначение адресов не поддержано, запрос пропущен"
                );
            }
            // Неизвестный тип или ранний IP-пакет (DATAGRAM) — RFC 9297,
            // §3.2 велит пропускать незнакомое молча, а пакет до готового
            // интерфейса всё равно некуда девать.
            _ => {}
        }
    }
}

fn interface_from(entries: Vec<capsule::AssignedAddress>) -> MasqueResult<PacketInterface> {
    let ipv4 = pick(&entries, IpAddr::is_ipv4, 32).ok_or_else(|| {
        MasqueError::malformed(
            "сервер не выдал адрес IPv4 (ADDRESS_ASSIGN): направлению уровня пакетов он \
             нужен всегда",
        )
    })?;
    let IpAddr::V4(ipv4_addr) = ipv4.0 else {
        unreachable!("отфильтровано предикатом is_ipv4")
    };

    let ipv6 = pick(&entries, IpAddr::is_ipv6, 128).map(|(addr, prefix)| {
        let IpAddr::V6(addr) = addr else {
            unreachable!("отфильтровано предикатом is_ipv6")
        };
        (addr, prefix)
    });

    Ok(PacketInterface {
        ipv4: (ipv4_addr, ipv4.1),
        ipv6,
        mtu: INTERFACE_MTU,
        // RFC 9484 не даёт способа сервера назвать сервер имён внутри
        // тоннеля (в отличие от `X-CSTP-DNS` у OpenConnect) — доменные имена
        // через это направление честно не разрешаются, а не уходят мимо
        // тоннеля молча (см. `crate::ip`).
        dns: Vec::new(),
    })
}

/// Первый адрес нужной версии, который не является отказом (RFC 9484, §4.7.2:
/// отказ на запрос — это всё-нулевой адрес с максимальной длиной префикса).
fn pick(
    entries: &[capsule::AssignedAddress],
    family: fn(&IpAddr) -> bool,
    max_prefix: u8,
) -> Option<(IpAddr, u8)> {
    entries
        .iter()
        .find(|e| family(&e.address) && !(e.address.is_unspecified() && e.prefix_len == max_prefix))
        .map(|e| (e.address, e.prefix_len))
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use tokio::io::{AsyncReadExt, duplex};

    use super::*;
    use crate::capsule::encode_capsule;
    use crate::ip::capsule::AssignedAddress;
    use crate::varint;

    fn encode_address_assign(addresses: &[AssignedAddress]) -> Bytes {
        let mut value = BytesMut::new();
        for a in addresses {
            varint::encode(a.request_id, &mut value);
            value.put_u8(match a.address {
                IpAddr::V4(_) => 4,
                IpAddr::V6(_) => 6,
            });
            match a.address {
                IpAddr::V4(v4) => value.put_slice(&v4.octets()),
                IpAddr::V6(v6) => value.put_slice(&v6.octets()),
            }
            value.put_u8(a.prefix_len);
        }
        encode_capsule(CAPSULE_TYPE_ADDRESS_ASSIGN, &value)
    }

    fn encode_route_advertisement(start: Ipv4Addr, end: Ipv4Addr) -> Bytes {
        let mut value = BytesMut::new();
        value.put_u8(4);
        value.put_slice(&start.octets());
        value.put_slice(&end.octets());
        value.put_u8(0);
        encode_capsule(CAPSULE_TYPE_ROUTE_ADVERTISEMENT, &value)
    }

    #[tokio::test]
    async fn a_server_that_assigns_ipv4_only_yields_an_interface_without_ipv6() {
        let (mut client, mut server) = duplex(4096);
        let mut reader = CapsuleReader::new();

        let assign = encode_address_assign(&[AssignedAddress {
            request_id: REQUEST_ID_IPV4,
            address: "203.0.113.9".parse().expect("адрес"),
            prefix_len: 32,
        }]);

        let task = tokio::spawn(async move { assign_interface(&mut client, &mut reader).await });

        // Клиент обязан прислать ADDRESS_REQUEST раньше, чем сервер ответит.
        let mut sent = vec![0u8; 64];
        let read = server.read(&mut sent).await.expect("запрос пришёл");
        assert!(read > 0);

        server.write_all(&assign).await.expect("ушло");

        let interface = task.await.expect("задача").expect("согласовано");
        assert_eq!(interface.ipv4, ("203.0.113.9".parse().expect("адрес"), 32));
        assert_eq!(interface.ipv6, None);
        assert_eq!(interface.mtu, INTERFACE_MTU);
        assert!(interface.dns.is_empty());
    }

    #[tokio::test]
    async fn a_server_that_never_assigns_an_address_is_a_named_error() {
        let (mut client, server) = duplex(4096);
        let mut reader = CapsuleReader::new();
        drop(server); // сервер закрыл соединение, так и не назначив адрес

        let err = assign_interface(&mut client, &mut reader)
            .await
            .expect_err("нет ADDRESS_ASSIGN");
        // Обрыв виден по-разному в зависимости от того, успел ли уйти
        // ADDRESS_REQUEST до того, как собеседник пропал: либо запись
        // проваливается сама (`Io`, «broken pipe»), либо поток закрывается
        // штатно на первом же чтении (`Disconnected`). Оба — обрыв связи, а
        // не поломка формата, и оба стоит повторить.
        assert!(
            matches!(err, MasqueError::Disconnected(_) | MasqueError::Io(_)),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_route_advertisement_before_the_address_does_not_stop_negotiation() {
        let (mut client, mut server) = duplex(4096);
        let mut reader = CapsuleReader::new();

        let route_capsule =
            encode_route_advertisement(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255));
        let assign = encode_address_assign(&[AssignedAddress {
            request_id: REQUEST_ID_IPV4,
            address: "203.0.113.9".parse().expect("адрес"),
            prefix_len: 32,
        }]);

        let task = tokio::spawn(async move { assign_interface(&mut client, &mut reader).await });

        let mut sent = vec![0u8; 64];
        let read = server.read(&mut sent).await.expect("запрос пришёл");
        assert!(read > 0);

        server.write_all(&route_capsule).await.expect("ушло");
        server.write_all(&assign).await.expect("ушло");

        let interface = task.await.expect("задача").expect("согласовано");
        assert_eq!(interface.ipv4.0, Ipv4Addr::new(203, 0, 113, 9));
    }
}
