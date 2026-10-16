//! macOS: таблица маршрутизации через `PF_ROUTE`.

mod pfroute;

use std::net::IpAddr;

use pfroute::Message;

use crate::error::{PlatformError, PlatformResult};
use crate::interface::DefaultRoute;
use crate::route::Route;

/// Ставит маршрут.
pub fn add(route: &Route) -> PlatformResult<()> {
    send(libc::RTM_ADD, route)
}

/// Снимает маршрут.
pub fn remove(route: &Route) -> PlatformResult<()> {
    send(libc::RTM_DELETE, route)
}

fn send(kind: libc::c_int, route: &Route) -> PlatformResult<()> {
    let mut message = Message::new(kind_byte(kind), flags(route));
    // Без номера снятие задело бы общий маршрут, а не свой.
    if route.scoped {
        message.scope_to(route.interface_index);
    }
    describe(&mut message, route);
    pfroute::talk(message, false).map(|_| ())
}

/// Вид сообщения помещается в байт.
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    reason = "вид сообщения помещается в байт"
)]
fn kind_byte(kind: libc::c_int) -> u8 {
    kind as u8
}

/// Спрашивает у ядра, как дойти до адреса.
pub fn route_to(destination: IpAddr) -> PlatformResult<DefaultRoute> {
    let mut message = Message::new(kind_byte(libc::RTM_GET), 0);
    message.address(libc::RTA_DST, &pfroute::sockaddr(destination));

    let reply = pfroute::talk(message, true)?;

    let gateway = pfroute::addresses(&reply)
        .into_iter()
        .find(|(slot, _)| *slot == libc::RTA_GATEWAY)
        .and_then(|(_, bytes)| pfroute::to_address(bytes));

    // Адрес интерфейса в ответе не назван; сокет выбирает тот же, глядя в ту же таблицу.
    let address = crate::interface::source_address_towards(destination).ok_or_else(|| {
        PlatformError::Interface("система не назвала адрес интерфейса".to_owned())
    })?;

    Ok(DefaultRoute {
        interface_index: pfroute::interface_index(&reply),
        address,
        gateway: gateway.unwrap_or(address),
        // Метрик в macOS нет: предпочтение решает длина префикса.
        metric: 0,
    })
}

/// Флаги маршрута; `RTF_HOST` нужен, когда маски нет.
fn flags(route: &Route) -> libc::c_int {
    let mut flags = libc::RTF_UP | libc::RTF_STATIC;
    if route.gateway.is_some() {
        flags |= libc::RTF_GATEWAY;
    }
    if is_host(route) {
        flags |= libc::RTF_HOST;
    }
    if route.scoped {
        flags |= libc::RTF_IFSCOPE;
    }
    flags
}

/// Маршрут ведёт до одного адреса, а не до подсети.
fn is_host(route: &Route) -> bool {
    let full = match route.destination.addr() {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    route.destination.prefix_len() == full
}

/// Дописывает назначение, шлюз и маску; порядок задан битами `rtm_addrs`.
fn describe(message: &mut Message, route: &Route) {
    message.address(libc::RTA_DST, &pfroute::sockaddr(route.destination.addr()));

    // Без шлюза («отдавай сюда») шлюзом становится сам интерфейс.
    match route.gateway {
        Some(gateway) => message.address(libc::RTA_GATEWAY, &pfroute::sockaddr(gateway)),
        None => message.address(
            libc::RTA_GATEWAY,
            &pfroute::sockaddr_link(route.interface_index),
        ),
    }

    if !is_host(route) {
        message.address(
            libc::RTA_NETMASK,
            &pfroute::sockaddr(route.destination.netmask()),
        );
    }
}

#[cfg(test)]
mod tests {
    use ipnet::IpNet;

    use super::*;

    #[test]
    fn a_host_route_carries_no_mask() {
        let route = Route::via_gateway(
            "203.0.113.5/32".parse::<IpNet>().expect("подсеть"),
            "192.168.0.1".parse().expect("шлюз"),
            7,
        );
        assert!(is_host(&route));
        assert_eq!(flags(&route) & libc::RTF_HOST, libc::RTF_HOST);
        assert_eq!(flags(&route) & libc::RTF_GATEWAY, libc::RTF_GATEWAY);
    }

    #[test]
    fn a_network_route_is_not_a_host_route() {
        let route = Route::via_interface("0.0.0.0/1".parse::<IpNet>().expect("подсеть"), 7);
        assert!(!is_host(&route));
        assert_eq!(flags(&route) & libc::RTF_HOST, 0);
        assert_eq!(flags(&route) & libc::RTF_GATEWAY, 0);
    }

    #[test]
    fn a_route_to_the_interface_names_it_as_the_gateway() {
        let route = Route::via_interface("0.0.0.0/1".parse::<IpNet>().expect("подсеть"), 7);

        let mut message = Message::new(kind_byte(libc::RTM_ADD), flags(&route));
        describe(&mut message, &route);
        let bytes = message.finish(1);

        let found = pfroute::addresses(&bytes);
        assert_eq!(found.len(), 3, "назначение, интерфейс и маска");
        assert!(
            pfroute::to_address(found[1].1).is_none(),
            "шлюзом стоит интерфейс, а не адрес"
        );
    }

    #[test]
    fn a_scoped_route_names_its_interface() {
        let mut route = Route::via_gateway(
            "0.0.0.0/0".parse::<IpNet>().expect("подсеть"),
            "172.20.10.1".parse().expect("шлюз"),
            11,
        );
        assert_eq!(flags(&route) & libc::RTF_IFSCOPE, 0, "обычный не привязан");

        route.scoped = true;
        assert_eq!(flags(&route) & libc::RTF_IFSCOPE, libc::RTF_IFSCOPE);

        let mut message = Message::new(kind_byte(libc::RTM_DELETE), flags(&route));
        message.scope_to(route.interface_index);
        let bytes = message.finish(1);
        assert_eq!(
            pfroute::interface_index(&bytes),
            11,
            "снятие не заденет общий"
        );
    }

    #[test]
    fn the_full_prefix_of_ipv6_is_a_host_too() {
        let route = Route::via_interface("2001:db8::1/128".parse::<IpNet>().expect("подсеть"), 7);
        assert!(is_host(&route));
    }
}
