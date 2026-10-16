//! Windows: `IP Helper`. Маршрут тоннеля добавляется с меньшей метрикой, а не заменяет чужой;
//! вместо `0.0.0.0/0` ставятся две половины — их префикс длиннее любого маршрута по умолчанию.

#![allow(unsafe_code, reason = "таблица маршрутизации через IP Helper")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net};
use windows::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, GetIpForwardEntry2, InitializeIpForwardEntry,
    MIB_IPFORWARD_ROW2,
};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, MIB_IPPROTO_NETMGMT, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
};

use crate::error::{PlatformError, PlatformResult};
use crate::route::Route;

/// Метрика маршрутов тоннеля: 0 — «считать по интерфейсу», 1 — самая предпочтительная явная.
const TUNNEL_METRIC: u32 = 1;

/// Две половины адресного пространства вместо маршрута по умолчанию.
pub fn default_route_halves() -> [Ipv4Net; 2] {
    [
        Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 1).unwrap_or_default(),
        Ipv4Net::new(Ipv4Addr::new(128, 0, 0, 0), 1).unwrap_or_default(),
    ]
}

/// Ставит маршрут.
pub fn add(route: &Route) -> PlatformResult<()> {
    let row = build_row(route);
    // SAFETY: `row` инициализирована `InitializeIpForwardEntry` и живёт до конца вызова.
    let result = unsafe { CreateIpForwardEntry2(&row) };

    match result {
        NO_ERROR => verify(route),
        // Остался после падения клиента: цель достигнута.
        ERROR_OBJECT_ALREADY_EXISTS => {
            tracing::debug!(destination = %route.destination, "маршрут уже стоял");
            Ok(())
        }
        code => Err(classify(
            code,
            format!("не удалось поставить {}", route.destination),
        )),
    }
}

/// Проверяет, что маршрут появился в таблице: `NO_ERROR` этого не обещает (запись с нулевым
/// временем жизни принимается и тут же исчезает).
fn verify(route: &Route) -> PlatformResult<()> {
    let mut row = build_row(route);

    // SAFETY: `row` заполнена ключевыми полями и живёт до конца вызова.
    match unsafe { GetIpForwardEntry2(&mut row) } {
        NO_ERROR => Ok(()),
        code => Err(PlatformError::Route(format!(
            "{} принят системой, но в таблице его нет (код {})",
            route.destination, code.0
        ))),
    }
}

/// Снимает маршрут.
pub fn remove(route: &Route) -> PlatformResult<()> {
    let row = build_row(route);
    // SAFETY: `row` инициализирована и живёт до конца вызова.
    let result = unsafe { DeleteIpForwardEntry2(&row) };

    match result {
        // Маршрута уже нет; система отвечает то «не найдено», то «нет такого файла».
        NO_ERROR | ERROR_NOT_FOUND | ERROR_FILE_NOT_FOUND => Ok(()),
        code => Err(PlatformError::rollback(
            "маршрут тоннеля",
            format!("{} (код {})", route.destination, code.0),
        )),
    }
}

/// Собирает запись таблицы. Через `InitializeIpForwardEntry` обязательно: иначе время жизни
/// нулевое, система принимает запись и сразу выбрасывает как просроченную.
fn build_row(route: &Route) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: `row` — локальная структура нужного типа.
    unsafe { InitializeIpForwardEntry(&mut row) };

    row.InterfaceIndex = route.interface_index;
    row.Metric = route.metric.unwrap_or(TUNNEL_METRIC);
    // Без протокола система считает запись недействительной.
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.SitePrefixLength = 0;

    match route.destination {
        IpNet::V4(v4) => {
            row.DestinationPrefix.PrefixLength = v4.prefix_len();
            row.DestinationPrefix.Prefix = sockaddr_v4(v4.network());
            row.NextHop = match route.gateway {
                Some(IpAddr::V4(gateway)) => sockaddr_v4(gateway),
                _ => sockaddr_v4(Ipv4Addr::UNSPECIFIED),
            };
        }
        IpNet::V6(v6) => {
            row.DestinationPrefix.PrefixLength = v6.prefix_len();
            row.DestinationPrefix.Prefix = sockaddr_v6(v6.network());
            row.NextHop = match route.gateway {
                Some(IpAddr::V6(gateway)) => sockaddr_v6(gateway),
                _ => sockaddr_v6(Ipv6Addr::UNSPECIFIED),
            };
        }
    }

    row
}

/// Собирает адрес IPv4 в виде, который понимает Windows.
pub(crate) fn sockaddr_v4(address: Ipv4Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(address.octets()),
                },
            },
            sin_zero: [0; 8],
        },
    }
}

/// Собирает адрес IPv6.
pub(crate) fn sockaddr_v6(address: Ipv6Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv6: SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: address.octets(),
                },
            },
            Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
        },
    }
}

/// Читает адрес из объединения Windows: семейство в общем поле выбирает читаемую половину.
pub(crate) fn from_sockaddr(address: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: `si_family` общее для обеих половин объединения.
    match unsafe { address.si_family } {
        AF_INET => {
            // SAFETY: семейство IPv4 — читается `Ipv4`.
            let raw = unsafe { address.Ipv4.sin_addr.S_un.S_addr };
            Some(IpAddr::from(raw.to_ne_bytes()))
        }
        AF_INET6 => {
            // SAFETY: семейство IPv6 — читается `Ipv6`.
            let octets = unsafe { address.Ipv6.sin6_addr.u.Byte };
            Some(IpAddr::from(octets))
        }
        _ => None,
    }
}

/// Переводит код Windows в понятную ошибку; 5 (`ERROR_ACCESS_DENIED`) — не администратор.
fn classify(code: WIN32_ERROR, context: String) -> PlatformError {
    if code == WIN32_ERROR(5) {
        return PlatformError::PermissionDenied(context);
    }
    PlatformError::Route(format!("{context} (код {})", code.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn halves_cover_everything_exactly_once() {
        let [low, high] = default_route_halves();
        assert_eq!(low.to_string(), "0.0.0.0/1");
        assert_eq!(high.to_string(), "128.0.0.0/1");

        for probe in ["0.0.0.1", "127.255.255.255", "8.8.8.8"] {
            let address: Ipv4Addr = probe.parse().expect("адрес");
            assert!(low.contains(&address), "{probe} не покрыт нижней половиной");
            assert!(!high.contains(&address));
        }
        for probe in ["128.0.0.0", "192.168.1.1", "255.255.255.255"] {
            let address: Ipv4Addr = probe.parse().expect("адрес");
            assert!(
                high.contains(&address),
                "{probe} не покрыт верхней половиной"
            );
            assert!(!low.contains(&address));
        }
    }

    #[test]
    fn halves_beat_a_default_route() {
        for half in default_route_halves() {
            assert!(half.prefix_len() > 0);
        }
    }

    #[test]
    fn row_carries_destination_and_interface() {
        let route = Route {
            destination: "10.0.0.0/8".parse().expect("подсеть"),
            gateway: None,
            interface_index: 42,
            metric: None,
            scoped: false,
        };
        let row = build_row(&route);

        assert_eq!(row.InterfaceIndex, 42);
        assert_eq!(row.DestinationPrefix.PrefixLength, 8);
        assert_eq!(row.Metric, TUNNEL_METRIC);
        assert_eq!(row.Protocol, MIB_IPPROTO_NETMGMT);
    }

    #[test]
    fn explicit_metric_wins() {
        let route = Route {
            destination: "10.0.0.0/8".parse().expect("подсеть"),
            gateway: None,
            interface_index: 1,
            metric: Some(500),
            scoped: false,
        };
        assert_eq!(build_row(&route).Metric, 500);
    }

    #[test]
    fn address_conversion_round_trips() {
        for probe in ["198.18.0.1", "0.0.0.0", "255.255.255.255"] {
            let original: Ipv4Addr = probe.parse().expect("адрес");
            assert_eq!(
                from_sockaddr(&sockaddr_v4(original)),
                Some(IpAddr::V4(original))
            );
        }

        let v6: Ipv6Addr = "2001:db8::1".parse().expect("адрес");
        assert_eq!(from_sockaddr(&sockaddr_v6(v6)), Some(IpAddr::V6(v6)));
    }

    #[test]
    fn access_denied_is_recognised() {
        let err = classify(WIN32_ERROR(5), "маршрут".to_owned());
        assert!(
            err.needs_privileges(),
            "нехватка прав должна быть видна: {err}"
        );
    }

    #[test]
    fn v6_row_uses_the_v6_prefix() {
        let route = Route {
            destination: "2001:db8::/32".parse().expect("подсеть"),
            gateway: None,
            interface_index: 3,
            metric: None,
            scoped: false,
        };
        let row = build_row(&route);
        assert_eq!(row.DestinationPrefix.PrefixLength, 32);
        assert!(from_sockaddr(&row.DestinationPrefix.Prefix).is_some_and(|ip| ip.is_ipv6()));
    }
}
