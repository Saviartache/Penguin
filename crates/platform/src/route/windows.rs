//! Windows: `IP Helper` и метрики интерфейсов.
//!
//! Маршрут по умолчанию через TUN ставится **не заменой** существующего, а
//! добавлением своего с меньшей метрикой. Разница принципиальная: заменить
//! чужой маршрут значит потерять его, а вместе с ним — возможность вернуть
//! всё как было, если клиент упадёт.
//!
//! Ещё одна тонкость: вместо `0.0.0.0/0` ставятся две половины, `0.0.0.0/1` и
//! `128.0.0.0/1`. Они покрывают всё то же самое, но их префикс длиннее, и
//! система выбирает их раньше **любого** маршрута по умолчанию — включая
//! чужой VPN-клиент, который тоже прописал себе метрику поменьше.

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

/// Метрика маршрутов тоннеля.
///
/// Ноль означает «считать по интерфейсу»; единица — самое низкое явное
/// значение, то есть самый предпочтительный маршрут.
const TUNNEL_METRIC: u32 = 1;

/// Две половины адресного пространства вместо маршрута по умолчанию.
///
/// Свободная функция с тестом: перепутать здесь границы легко, а последствие
/// — половина трафика мимо тоннеля, причём та половина, которую никто не
/// проверяет.
pub fn default_route_halves() -> [Ipv4Net; 2] {
    [
        Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 1).unwrap_or_default(),
        Ipv4Net::new(Ipv4Addr::new(128, 0, 0, 0), 1).unwrap_or_default(),
    ]
}

/// Ставит маршрут.
pub fn add(route: &Route) -> PlatformResult<()> {
    let row = build_row(route);
    let result = unsafe { CreateIpForwardEntry2(&row) };

    match result {
        NO_ERROR => verify(route),
        // Маршрут уже стоит — например, после падения клиента. Это не
        // ошибка: цель достигнута.
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

/// Проверяет, что маршрут и правда появился в таблице.
///
/// `NO_ERROR` от `CreateIpForwardEntry2` этого **не** обещает: запись с
/// нулевым временем жизни принимается и тут же исчезает. Без проверки такое
/// не видно ниоткуда — клиент говорит «подключено», а трафику идти некуда, и
/// при включённом kill switch интернет пропадает совсем.
fn verify(route: &Route) -> PlatformResult<()> {
    let mut row = build_row(route);

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
    let result = unsafe { DeleteIpForwardEntry2(&row) };

    match result {
        // Маршрута уже нет — снимать нечего, и это тоже успех. Кодов на это
        // два: система отвечает то «не найдено», то «нет такого файла».
        NO_ERROR | ERROR_NOT_FOUND | ERROR_FILE_NOT_FOUND => Ok(()),
        code => {
            // Оставленный маршрут — это сеть, которая у пользователя не
            // работает после выхода из клиента. Такое молчанием не покрывают.
            Err(PlatformError::rollback(
                "маршрут тоннеля",
                format!("{} (код {})", route.destination, code.0),
            ))
        }
    }
}

/// Собирает запись таблицы маршрутизации.
///
/// # Почему нельзя просто заполнить поля
///
/// `CreateIpForwardEntry2` требует, чтобы запись сначала прошла через
/// `InitializeIpForwardEntry`. Требование не формальное: там выставляются
/// `ValidLifetime` и `PreferredLifetime` — время жизни маршрута. У записи,
/// собранной с нуля, они равны нулю, и система такую запись **принимает**,
/// вернув `NO_ERROR`, а потом сразу выбрасывает как просроченную.
///
/// Снаружи это выглядит так: клиент отчитался об успехе, интернета нет, а при
/// отключении маршруты не снимаются — их уже нет.
fn build_row(route: &Route) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };

    row.InterfaceIndex = route.interface_index;
    row.Metric = route.metric.unwrap_or(TUNNEL_METRIC);
    // Обязательно: без этого система считает запись недействительной и
    // отвергает её с невнятным кодом.
    row.Protocol = MIB_IPPROTO_NETMGMT;
    // Длина префикса участка не используется; она должна быть не больше длины
    // префикса назначения, а ноль подходит всегда.
    row.SitePrefixLength = 0;

    match route.destination {
        IpNet::V4(v4) => {
            row.DestinationPrefix.PrefixLength = v4.prefix_len();
            row.DestinationPrefix.Prefix = sockaddr_v4(v4.network());
            row.NextHop = match route.gateway {
                Some(IpAddr::V4(gateway)) => sockaddr_v4(gateway),
                // Маршрут «на интерфейс»: за TUN никого нет, следующего узла
                // не существует.
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

/// Читает адрес из объединения Windows.
///
/// Семейство лежит в общем поле и определяет, какую из половин объединения
/// можно читать. Прочитать не ту — значит получить мусор.
pub(crate) fn from_sockaddr(address: &SOCKADDR_INET) -> Option<IpAddr> {
    match unsafe { address.si_family } {
        AF_INET => {
            let raw = unsafe { address.Ipv4.sin_addr.S_un.S_addr };
            Some(IpAddr::from(raw.to_ne_bytes()))
        }
        AF_INET6 => {
            let octets = unsafe { address.Ipv6.sin6_addr.u.Byte };
            Some(IpAddr::from(octets))
        }
        _ => None,
    }
}

/// Переводит код Windows в понятную ошибку.
fn classify(code: WIN32_ERROR, context: String) -> PlatformError {
    // 5 — `ERROR_ACCESS_DENIED`. Самая частая причина: клиент запущен не от
    // администратора.
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
        // Перепутанные границы означают половину трафика мимо тоннеля —
        // причём ту половину, которую никто не проверяет.
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
        // Префикс длиннее нулевого, значит система выберет их раньше любого
        // `0.0.0.0/0` — включая чужой VPN-клиент с низкой метрикой.
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
        };
        let row = build_row(&route);
        assert_eq!(row.DestinationPrefix.PrefixLength, 32);
        assert!(from_sockaddr(&row.DestinationPrefix.Prefix).is_some_and(|ip| ip.is_ipv6()));
    }
}
