//! Linux: таблица маршрутизации через netlink.

mod netlink;

use std::net::IpAddr;

use netlink::{Message, RouteHeader};

use crate::error::{PlatformError, PlatformResult};
use crate::interface::DefaultRoute;
use crate::route::Route;

/// Поставить маршрут.
const RTM_NEWROUTE: u16 = 24;
/// Снять маршрут.
const RTM_DELROUTE: u16 = 25;
/// Спросить про маршрут.
const RTM_GETROUTE: u16 = 26;

/// Куда.
const RTA_DST: u16 = 1;
/// Через какой интерфейс.
const RTA_OIF: u16 = 4;
/// Через какой узел.
const RTA_GATEWAY: u16 = 5;
/// Метрика.
const RTA_PRIORITY: u16 = 6;
/// Каким адресом выходить.
const RTA_PREFSRC: u16 = 7;

/// Ставит маршрут.
pub fn add(route: &Route) -> PlatformResult<()> {
    let mut message = Message::new(
        RTM_NEWROUTE,
        netlink::NLM_F_ACK | netlink::NLM_F_CREATE | netlink::NLM_F_EXCL,
        &header(route),
    );
    describe(&mut message, route);
    netlink::talk(message).map(|_| ())
}

/// Снимает маршрут.
pub fn remove(route: &Route) -> PlatformResult<()> {
    let mut message = Message::new(RTM_DELROUTE, netlink::NLM_F_ACK, &header(route));
    describe(&mut message, route);
    netlink::talk(message).map(|_| ())
}

/// Спрашивает у ядра, как дойти до адреса.
pub fn route_to(destination: IpAddr) -> PlatformResult<DefaultRoute> {
    let target = address_bytes(destination);

    let mut message = Message::new(
        RTM_GETROUTE,
        0,
        &RouteHeader {
            family: family(destination),
            #[allow(
                clippy::cast_possible_truncation,
                reason = "длина адреса в битах не выходит за 128"
            )]
            destination_len: (target.len() * 8) as u8,
            ..RouteHeader::default()
        },
    );
    message.attribute(RTA_DST, &target);

    let reply = netlink::talk(message)?;
    let payload = netlink::route_payload(&reply).ok_or_else(|| {
        PlatformError::Interface(format!("ядро не описало маршрут до {destination}"))
    })?;

    let mut interface_index = 0;
    let mut gateway = None;
    let mut source = None;
    let mut metric = 0;

    for (kind, value) in netlink::attributes(payload) {
        match kind {
            RTA_OIF => interface_index = number(value).unwrap_or(0),
            RTA_GATEWAY => gateway = to_address(value),
            RTA_PREFSRC => source = to_address(value),
            RTA_PRIORITY => metric = number(value).unwrap_or(0),
            _ => {}
        }
    }

    // Ядро называет адрес не всегда; сокет выбирает тот же, глядя в ту же таблицу.
    let address = source
        .or_else(|| crate::interface::source_address_towards(destination))
        .ok_or_else(|| {
            PlatformError::Interface("система не назвала адрес интерфейса".to_owned())
        })?;

    Ok(DefaultRoute {
        interface_index,
        address,
        gateway: gateway.unwrap_or(address),
        metric,
    })
}

/// Общая часть описания маршрута.
fn header(route: &Route) -> RouteHeader {
    const RTPROT_STATIC: u8 = 4;
    const RTN_UNICAST: u8 = 1;
    const RT_TABLE_MAIN: u8 = 254;
    const RT_SCOPE_UNIVERSE: u8 = 0;
    const RT_SCOPE_LINK: u8 = 253;

    RouteHeader {
        family: family(route.destination.addr()),
        destination_len: route.destination.prefix_len(),
        source_len: 0,
        tos: 0,
        table: RT_TABLE_MAIN,
        protocol: RTPROT_STATIC,
        // Без шлюза нужна область «link»: иначе ядро ждёт шлюз и отвечает `EINVAL`.
        scope: if route.gateway.is_some() {
            RT_SCOPE_UNIVERSE
        } else {
            RT_SCOPE_LINK
        },
        kind: RTN_UNICAST,
        flags: 0,
    }
}

/// Дописывает адрес, интерфейс, шлюз и метрику.
fn describe(message: &mut Message, route: &Route) {
    message.attribute(RTA_DST, &address_bytes(route.destination.addr()));
    message.attribute(RTA_OIF, &route.interface_index.to_ne_bytes());

    if let Some(gateway) = route.gateway {
        message.attribute(RTA_GATEWAY, &address_bytes(gateway));
    }
    if let Some(metric) = route.metric {
        message.attribute(RTA_PRIORITY, &metric.to_ne_bytes());
    }
}

/// Семейство адресов.
fn family(address: IpAddr) -> u8 {
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        reason = "семейство адресов помещается в байт"
    )]
    match address {
        IpAddr::V4(_) => libc::AF_INET as u8,
        IpAddr::V6(_) => libc::AF_INET6 as u8,
    }
}

/// Адрес в виде netlink: только байты, семейство лежит в заголовке.
fn address_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// Адрес из свойства ответа; свойство не той длины — не адрес.
fn to_address(value: &[u8]) -> Option<IpAddr> {
    match value.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(value).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(value).ok()?)),
        _ => None,
    }
}

/// Число из свойства ответа.
fn number(value: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(<[u8; 4]>::try_from(value).ok()?))
}

#[cfg(test)]
mod tests {
    use ipnet::IpNet;

    use super::*;

    #[test]
    fn a_route_without_a_gateway_stays_on_the_wire() {
        let route = Route::via_interface("0.0.0.0/1".parse::<IpNet>().expect("подсеть"), 7);
        assert_eq!(header(&route).scope, 253);

        let route = Route::via_gateway(
            "203.0.113.5/32".parse::<IpNet>().expect("подсеть"),
            "192.168.0.1".parse().expect("шлюз"),
            7,
        );
        assert_eq!(header(&route).scope, 0);
    }

    #[test]
    fn the_prefix_length_comes_from_the_destination() {
        let route = Route::via_interface("10.0.0.0/8".parse::<IpNet>().expect("подсеть"), 1);
        assert_eq!(header(&route).destination_len, 8);
    }

    #[test]
    fn addresses_travel_without_their_family() {
        assert_eq!(
            address_bytes("203.0.113.5".parse().expect("адрес")),
            vec![203, 0, 113, 5]
        );
        assert_eq!(address_bytes("::1".parse().expect("адрес")).len(), 16);
    }

    #[test]
    fn a_property_of_the_wrong_length_is_not_an_address() {
        assert!(to_address(&[1, 2, 3]).is_none());
        assert!(to_address(&[]).is_none());
        assert_eq!(
            to_address(&[203, 0, 113, 5]),
            Some("203.0.113.5".parse().expect("адрес"))
        );
    }
}
