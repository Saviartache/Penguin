//! macOS: таблица маршрутизации через `PF_ROUTE`.

mod pfroute;

use std::net::IpAddr;

use pfroute::Message;

use crate::error::{PlatformError, PlatformResult};
use crate::interface::DefaultRoute;
use crate::route::Route;

/// Ставит маршрут.
pub fn add(route: &Route) -> PlatformResult<()> {
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        reason = "вид сообщения помещается в байт"
    )]
    let mut message = Message::new(libc::RTM_ADD as u8, flags(route));
    describe(&mut message, route);
    pfroute::talk(message, false).map(|_| ())
}

/// Снимает маршрут.
pub fn remove(route: &Route) -> PlatformResult<()> {
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        reason = "вид сообщения помещается в байт"
    )]
    let mut message = Message::new(libc::RTM_DELETE as u8, flags(route));
    describe(&mut message, route);
    pfroute::talk(message, false).map(|_| ())
}

/// Спрашивает у ядра, как дойти до адреса.
pub fn route_to(destination: IpAddr) -> PlatformResult<DefaultRoute> {
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        reason = "вид сообщения помещается в байт"
    )]
    let mut message = Message::new(libc::RTM_GET as u8, 0);
    message.address(libc::RTA_DST, &pfroute::sockaddr(destination));

    let reply = pfroute::talk(message, true)?;

    let gateway = pfroute::addresses(&reply)
        .into_iter()
        .find(|(slot, _)| *slot == libc::RTA_GATEWAY)
        .and_then(|(_, bytes)| pfroute::to_address(bytes));

    // Адрес интерфейса ядро в ответе не называет: его спрашивают у сокета —
    // он выбирает тот же самый, потому что смотрит в ту же таблицу.
    let address = crate::interface::source_address_towards(destination).ok_or_else(|| {
        PlatformError::Interface("система не назвала адрес интерфейса".to_owned())
    })?;

    Ok(DefaultRoute {
        interface_index: pfroute::interface_index(&reply),
        address,
        // Маршрут «на интерфейс» шлюза не имеет: следующего узла за ним нет.
        gateway: gateway.unwrap_or(address),
        // Метрик у маршрутов в macOS нет — предпочтение решает длина
        // префикса, и поэтому же тоннель ставится двумя половинами.
        metric: 0,
    })
}

/// Флаги маршрута.
fn flags(route: &Route) -> libc::c_int {
    let mut flags = libc::RTF_UP | libc::RTF_STATIC;
    if route.gateway.is_some() {
        flags |= libc::RTF_GATEWAY;
    }
    if is_host(route) {
        // Маршрут до одного адреса. Без этого флага ядро ждёт маску, а
        // маршрут до узла её не имеет.
        flags |= libc::RTF_HOST;
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

/// Дописывает назначение, шлюз и маску.
///
/// Порядок обязателен: ядро читает адреса подряд и разбирает их по порядку
/// битов в `rtm_addrs`, а не по содержимому.
fn describe(message: &mut Message, route: &Route) {
    message.address(libc::RTA_DST, &pfroute::sockaddr(route.destination.addr()));

    // За TUN никого нет, и шлюзом маршрута становится сам интерфейс: это
    // единственный способ сказать «отдавай сюда» без адреса следующего узла.
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
        // Маршрут до одного адреса маски не имеет, и ядро её не ждёт.
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
        // За TUN никого нет: шлюза у такого маршрута тоже нет.
        assert_eq!(flags(&route) & libc::RTF_GATEWAY, 0);
    }

    #[test]
    fn a_route_to_the_interface_names_it_as_the_gateway() {
        // Это единственный способ сказать «отдавай сюда», не имея адреса
        // следующего узла.
        let route = Route::via_interface("0.0.0.0/1".parse::<IpNet>().expect("подсеть"), 7);

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let mut message = Message::new(libc::RTM_ADD as u8, flags(&route));
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
    fn the_full_prefix_of_ipv6_is_a_host_too() {
        let route = Route::via_interface("2001:db8::1/128".parse::<IpNet>().expect("подсеть"), 7);
        assert!(is_host(&route));
    }
}
