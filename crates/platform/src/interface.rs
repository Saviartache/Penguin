//! Сетевые интерфейсы, шлюз по умолчанию, метрики. Нужны, чтобы прямой
//! трафик знал, куда идти.
//!
//! Когда TUN становится маршрутом по умолчанию, «выйти наружу» перестаёт быть
//! очевидным действием: обычный сокет уедет в тоннель. Прямому выходу нужен
//! адрес физического интерфейса, к которому он привяжется, — и этот адрес
//! надо запомнить **до** поднятия тоннеля, пока система ещё отвечает на
//! вопрос честно.

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
    /// Метрика маршрута.
    ///
    /// Маршрут тоннеля должен получить метрику **меньше**, иначе система
    /// продолжит ходить мимо него.
    pub metric: u32,
}

/// Находит интерфейс, через который машина выходит наружу.
///
/// Спрашивается «как дойти до этого адреса», а не «какой маршрут по
/// умолчанию»: у машины бывает несколько маршрутов по умолчанию, и выбирает
/// между ними всё равно система. Адрес взят из подсети, отведённой под
/// документацию (RFC 5737), — соединяться с ним никто не будет.
pub fn default_route() -> PlatformResult<DefaultRoute> {
    let probe: IpAddr = "192.0.2.1"
        .parse()
        .map_err(|_| PlatformError::Interface("не разбирается пробный адрес".to_owned()))?;
    route_to(probe)
}

/// Имя интерфейса, если путь наружу ведёт через **чужой** тоннель.
///
/// `None` — путь ведёт обычным интерфейсом, и это норма.
///
/// Спрашивается до того, как поднят свой адаптер, поэтому «тоннель» здесь и
/// значит «чужой»: другой VPN-клиент уже забрал себе маршрут по умолчанию.
/// Наше соединение с сервером уйдёт внутрь него, и что с ним станет — решает
/// он. Клиенты этого рода по умолчанию режут QUIC, то есть UDP на 443, а
/// именно им ходят Hysteria 2, TUIC и MASQUE. Снаружи это неотличимо от
/// недоступного сервера: рукопожатие не завершается, и переживает это любую
/// перенастройку нашей стороны.
///
/// На Windows не проверяется: имя адаптеру там даёт производитель, и
/// опознать по нему тоннель нельзя.
#[cfg(unix)]
pub fn foreign_tunnel(route: &DefaultRoute) -> Option<String> {
    let name = interface_name(route.interface_index)?;
    is_tunnel(&name).then_some(name)
}

#[cfg(not(unix))]
pub fn foreign_tunnel(_route: &DefaultRoute) -> Option<String> {
    None
}

/// Имя интерфейса по его номеру.
#[cfg(unix)]
#[allow(unsafe_code, reason = "имя интерфейса по номеру даёт только libc")]
fn interface_name(index: u32) -> Option<String> {
    let mut buffer = [0 as libc::c_char; libc::IF_NAMESIZE];
    if unsafe { libc::if_indextoname(index, buffer.as_mut_ptr()) }.is_null() {
        return None;
    }
    let length = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    #[allow(
        clippy::cast_sign_loss,
        reason = "имя интерфейса система составляет из ASCII"
    )]
    let bytes: Vec<u8> = buffer[..length].iter().map(|byte| *byte as u8).collect();
    String::from_utf8(bytes).ok()
}

/// Тоннельный ли это интерфейс — по имени, которое даёт ему система.
///
/// Свободная функция с тестом: ошибка здесь означает либо предупреждение при
/// каждом обычном подключении, либо молчание там, ради чего всё затевалось.
#[cfg(unix)]
fn is_tunnel(name: &str) -> bool {
    // `utun` — macOS, `tun`/`wg` — Linux, `ppp` и `ipsec` — оба. Физические
    // интерфейсы называются иначе: `en`, `eth`, `wl`, `bridge`.
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

    // Интерфейс не задаём: пусть система сама решит, каким выйти. В этом и
    // вопрос — мы спрашиваем «как дойти», а не «дойди вот этим».
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

/// Каким адресом машина выйдет к указанному узлу.
///
/// Спрашивается у сокета, а не у таблицы маршрутизации: `connect` на UDP не
/// отправляет ни байта, но заставляет систему выбрать исходящий интерфейс —
/// тот самый, которым она пошла бы на самом деле. Своя же копия этого выбора,
/// собранная перебором интерфейсов, однажды разошлась бы с системой.
///
/// `None` — маршрута до узла нет вовсе.
#[cfg(unix)]
pub(crate) fn source_address_towards(destination: IpAddr) -> Option<IpAddr> {
    let bind = if destination.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let socket = std::net::UdpSocket::bind(bind).ok()?;
    // Порт любой: до отправки дело не дойдёт, а выбор интерфейса от него не
    // зависит.
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
        // Ложное срабатывание здесь — предупреждение о чужом VPN при каждом
        // обычном подключении, и читать его перестанут в тот же день.
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
        // На машине с сетью маршрут наружу обязан находиться: без него
        // прямому выходу некуда привязываться.
        match default_route() {
            Ok(route) => {
                assert!(route.interface_index > 0);
                assert!(
                    !route.address.is_unspecified(),
                    "адрес интерфейса не назван"
                );
            }
            Err(err) => {
                // Машина без сети — законное состояние для теста.
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
        // Соединяться с ним никто не будет — это подсеть из RFC 5737.
        let probe: IpAddr = "192.0.2.1".parse().expect("адрес");
        assert!(!probe.is_loopback());
        assert!(!probe.is_unspecified());
    }
}
