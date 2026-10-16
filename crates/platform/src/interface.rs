//! Физический интерфейс, шлюз и метрика: прямой выход должен знать, куда идти, когда TUN —
//! маршрут по умолчанию. Запоминается до подъёма тоннеля.

use std::net::IpAddr;

use crate::error::{PlatformError, PlatformResult};

/// Физический интерфейс, через который машина выходит наружу.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    /// Индекс интерфейса в системе.
    pub interface_index: u32,
    /// Адрес интерфейса — к нему привязывается прямой выход.
    pub address: IpAddr,
    /// Адрес шлюза.
    pub gateway: IpAddr,
    /// Метрика маршрута; у маршрута тоннеля она должна быть меньше.
    pub metric: u32,
}

/// Находит интерфейс выхода наружу: спрашивается путь до адреса из RFC 5737, а не «маршрут по умолчанию».
pub fn default_route() -> PlatformResult<DefaultRoute> {
    let probe: IpAddr = "192.0.2.1"
        .parse()
        .map_err(|_| PlatformError::Interface("не разбирается пробный адрес".to_owned()))?;
    route_to(probe)
}

/// Имя интерфейса, если путь наружу ведёт через чужой тоннель (чужой VPN режет QUIC); на Windows не проверяется.
#[cfg(unix)]
pub fn foreign_tunnel(route: &DefaultRoute) -> Option<String> {
    let name = interface_name(route.interface_index)?;
    is_tunnel(&name).then_some(name)
}

/// Имя интерфейса, если путь наружу ведёт через чужой тоннель (чужой VPN режет QUIC); на Windows не проверяется.
#[cfg(not(unix))]
pub fn foreign_tunnel(_route: &DefaultRoute) -> Option<String> {
    None
}

/// Имя интерфейса по его номеру.
#[cfg(unix)]
#[allow(unsafe_code, reason = "имя интерфейса по номеру даёт только libc")]
fn interface_name(index: u32) -> Option<String> {
    let mut buffer = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: буфер `IF_NAMESIZE` — то, чего требует `if_indextoname`.
    if unsafe { libc::if_indextoname(index, buffer.as_mut_ptr()) }.is_null() {
        return None;
    }
    let length = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    #[allow(clippy::cast_sign_loss, reason = "имя интерфейса — ASCII")]
    let bytes: Vec<u8> = buffer[..length].iter().map(|byte| *byte as u8).collect();
    String::from_utf8(bytes).ok()
}

/// Тоннельный ли интерфейс — по имени (`utun`, `tun`, `wg`, `ppp`, `ipsec`).
#[cfg(unix)]
fn is_tunnel(name: &str) -> bool {
    const PREFIXES: [&str; 5] = ["utun", "tun", "wg", "ppp", "ipsec"];
    PREFIXES.iter().any(|prefix| {
        name.strip_prefix(prefix)
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// Находит интерфейс, через который машина дойдёт до указанного адреса.
#[cfg(windows)]
#[allow(unsafe_code, reason = "запрос таблицы маршрутизации через IP Helper")]
pub fn route_to(destination: IpAddr) -> PlatformResult<DefaultRoute> {
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2};
    use windows::Win32::Networking::WinSock::SOCKADDR_INET;

    use crate::route::windows::{from_sockaddr, sockaddr_v4, sockaddr_v6};

    let target = match destination {
        IpAddr::V4(v4) => sockaddr_v4(v4),
        IpAddr::V6(v6) => sockaddr_v6(v6),
    };

    let mut row = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();

    // SAFETY: все указатели ведут на локальные структуры; интерфейс не задан — выбирает система.
    let code = unsafe {
        GetBestRoute2(
            None,
            0,
            None,
            std::ptr::from_ref(&target),
            0,
            &mut row,
            &mut source,
        )
    };
    if code != NO_ERROR {
        return Err(PlatformError::Interface(format!(
            "не найден маршрут до {destination} (код {})",
            code.0
        )));
    }

    let address = from_sockaddr(&source).ok_or_else(|| {
        PlatformError::Interface("система не назвала адрес интерфейса".to_owned())
    })?;
    let gateway = from_sockaddr(&row.NextHop).unwrap_or(address);

    Ok(DefaultRoute {
        interface_index: row.InterfaceIndex,
        address,
        gateway,
        metric: row.Metric,
    })
}

/// Находит интерфейс до адреса.
#[cfg(target_os = "linux")]
pub fn route_to(destination: IpAddr) -> PlatformResult<DefaultRoute> {
    crate::route::linux::route_to(destination)
}

/// Находит интерфейс до адреса.
#[cfg(target_os = "macos")]
pub fn route_to(destination: IpAddr) -> PlatformResult<DefaultRoute> {
    crate::route::macos::route_to(destination)
}

/// Находит интерфейс до адреса.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn route_to(destination: IpAddr) -> PlatformResult<DefaultRoute> {
    let _ = destination;
    Err(PlatformError::Unsupported("определение маршрута"))
}

/// Исходящий адрес к узлу: `connect` на UDP не шлёт байт, но заставляет систему выбрать интерфейс.
#[cfg(unix)]
pub(crate) fn source_address_towards(destination: IpAddr) -> Option<IpAddr> {
    let bind = if destination.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let socket = std::net::UdpSocket::bind(bind).ok()?;
    socket.connect((destination, 53)).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

#[cfg(all(test, unix))]
mod tunnel_names {
    use super::is_tunnel;

    #[test]
    fn tunnel_interfaces_are_recognised() {
        for name in ["utun0", "utun8", "tun0", "wg0", "ppp0", "ipsec0"] {
            assert!(is_tunnel(name), "{name}");
        }
    }

    #[test]
    fn physical_interfaces_are_left_alone() {
        for name in ["en0", "eth0", "wlan0", "bridge100", "lo0", "awdl0", "utun"] {
            assert!(!is_tunnel(name), "{name}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn finds_the_way_out() {
        match default_route() {
            Ok(route) => {
                assert!(route.interface_index > 0);
                assert!(
                    !route.address.is_unspecified(),
                    "адрес интерфейса не назван"
                );
            }
            Err(err) => {
                // Машина без сети — законное состояние.
                assert!(
                    err.to_string().contains("маршрут"),
                    "неожиданная ошибка: {err}"
                );
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn loopback_route_points_at_loopback() {
        let route = route_to("127.0.0.1".parse().expect("адрес")).expect("маршрут до петли есть");
        assert!(
            route.address.is_loopback(),
            "адрес не из петли: {}",
            route.address
        );
    }

    #[test]
    fn probe_address_is_documentation_only() {
        let probe: IpAddr = "192.0.2.1".parse().expect("адрес");
        assert!(!probe.is_loopback());
        assert!(!probe.is_unspecified());
    }
}
