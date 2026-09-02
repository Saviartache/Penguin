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
#[cfg(not(windows))]
pub fn route_to(destination: IpAddr) -> PlatformResult<DefaultRoute> {
    let _ = destination;
    Err(PlatformError::Unsupported("определение маршрута"))
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
