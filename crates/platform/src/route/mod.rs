//! Таблица маршрутизации: поставить маршруты тоннеля и гарантированно снять, в том числе при аварии.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

use std::net::IpAddr;

use ipnet::IpNet;
use parking_lot::Mutex;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
use crate::error::PlatformError;
use crate::error::PlatformResult;
use crate::interface::DefaultRoute;

/// Один маршрут.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Куда.
    pub destination: IpNet,
    /// Через какой узел; `None` — маршрут «на интерфейс» (за TUN никого нет).
    pub gateway: Option<IpAddr>,
    /// Через какой интерфейс.
    pub interface_index: u32,
    /// Метрика; `None` — самая предпочтительная.
    pub metric: Option<u32>,
    /// Только для сокетов, привязанных к интерфейсу (`RTF_IFSCOPE` в macOS); прочим не виден.
    pub scoped: bool,
}

impl Route {
    /// Маршрут на интерфейс.
    pub fn via_interface(destination: IpNet, interface_index: u32) -> Self {
        Self {
            destination,
            gateway: None,
            interface_index,
            metric: None,
            scoped: false,
        }
    }

    /// Маршрут через шлюз.
    pub fn via_gateway(destination: IpNet, gateway: IpAddr, interface_index: u32) -> Self {
        Self {
            destination,
            gateway: Some(gateway),
            interface_index,
            metric: None,
            scoped: false,
        }
    }
}

/// Поставленные клиентом маршруты; снимаются отсюда же, в том числе из `Drop`.
#[derive(Debug, Default)]
pub struct RouteGuard {
    installed: Mutex<Vec<Route>>,
}

impl RouteGuard {
    /// Пустой список.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ставит маршрут и запоминает его.
    pub fn add(&self, route: Route) -> PlatformResult<()> {
        add_route(&route)?;
        tracing::debug!(destination = %route.destination, "маршрут поставлен");
        self.installed.lock().push(route);
        Ok(())
    }

    /// Проводит адреса мимо тоннеля прежним путём наружу; без этого пакеты до сервера
    /// зациклились бы через TUN. Длинный префикс узла побеждает любой другой маршрут.
    pub fn pin_outside(&self, addresses: &[IpAddr], outside: &DefaultRoute) -> PlatformResult<()> {
        for address in addresses {
            // Тоннель забирает только IPv4 (`default_halves`): адрес другого семейства
            // в тоннель не попадёт, а шлюз IPv4 для него негоден.
            if address.is_ipv4() != outside.gateway.is_ipv4() {
                tracing::debug!(%address, "адрес другого семейства — маршрут наружу не нужен");
                continue;
            }
            let route = Route::via_gateway(
                IpNet::from(*address),
                outside.gateway,
                outside.interface_index,
            );
            // Маршрут через физический интерфейс переживает убитый клиент, и шлюз в нём мог
            // устареть: сначала снять такой же.
            let _ = remove_route(&route);
            self.add(route)?;
        }
        Ok(())
    }

    /// Оставляет прямому выходу путь наружу: его сокеты привязаны к физическому интерфейсу,
    /// а macOS ищет им маршрут только среди привязанных к нему же. Своего такого у основного
    /// интерфейса нет — без этого маршрута всё «напрямую» получает `Network is unreachable`.
    #[cfg(target_os = "macos")]
    pub fn keep_outside_default(&self, outside: &DefaultRoute) -> PlatformResult<()> {
        let destination = IpNet::V4(ipnet::Ipv4Net::default());
        let mut route = if outside.gateway == outside.address {
            Route::via_interface(destination, outside.interface_index)
        } else {
            Route::via_gateway(destination, outside.gateway, outside.interface_index)
        };
        route.scoped = true;

        match self.add(route) {
            Err(crate::error::PlatformError::RouteExists) => {
                tracing::debug!("привязанный маршрут наружу уже есть у системы");
                Ok(())
            }
            result => result,
        }
    }

    /// На других системах прямой выход находит путь сам.
    #[cfg(not(target_os = "macos"))]
    pub fn keep_outside_default(&self, _outside: &DefaultRoute) -> PlatformResult<()> {
        Ok(())
    }

    /// Заворачивает весь трафик в интерфейс двумя половинами: префикс длиннее маршрута
    /// по умолчанию, в том числе чужого VPN.
    pub fn capture_all(&self, interface_index: u32) -> PlatformResult<()> {
        for half in default_halves() {
            self.add(Route::via_interface(half, interface_index))?;
        }
        Ok(())
    }

    /// Снимает всё поставленное, не останавливаясь на ошибках; возвращает первую.
    pub fn restore(&self) -> PlatformResult<()> {
        let routes = std::mem::take(&mut *self.installed.lock());
        let mut first_error = None;

        for route in routes.iter().rev() {
            if let Err(err) = remove_route(route) {
                tracing::error!(destination = %route.destination, %err, "маршрут не снят");
                first_error.get_or_insert(err);
            }
        }

        first_error.map_or(Ok(()), Err)
    }

    /// Сколько маршрутов поставлено.
    pub fn len(&self) -> usize {
        self.installed.lock().len()
    }

    /// Ничего не поставлено.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        if !self.is_empty()
            && let Err(err) = self.restore()
        {
            tracing::error!(%err, "маршруты остались в системе");
        }
    }
}

/// Половины адресного пространства вместо маршрута по умолчанию.
pub fn default_halves() -> Vec<IpNet> {
    #[cfg(windows)]
    {
        windows::default_route_halves()
            .into_iter()
            .map(IpNet::V4)
            .collect()
    }
    #[cfg(not(windows))]
    {
        vec![
            "0.0.0.0/1"
                .parse()
                .unwrap_or_else(|_| IpNet::V4(Default::default())),
            "128.0.0.0/1"
                .parse()
                .unwrap_or_else(|_| IpNet::V4(Default::default())),
        ]
    }
}

fn add_route(route: &Route) -> PlatformResult<()> {
    #[cfg(windows)]
    {
        windows::add(route)
    }
    #[cfg(target_os = "linux")]
    {
        linux::add(route)
    }
    #[cfg(target_os = "macos")]
    {
        macos::add(route)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = route;
        Err(PlatformError::Unsupported("постановка маршрута"))
    }
}

fn remove_route(route: &Route) -> PlatformResult<()> {
    #[cfg(windows)]
    {
        windows::remove(route)
    }
    #[cfg(target_os = "linux")]
    {
        linux::remove(route)
    }
    #[cfg(target_os = "macos")]
    {
        macos::remove(route)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = route;
        Err(PlatformError::Unsupported("снятие маршрута"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pinned_address_becomes_a_host_route() {
        let address: IpAddr = "203.0.113.10".parse().expect("адрес");
        let route = Route::via_gateway(
            IpNet::from(address),
            "192.168.0.1".parse().expect("шлюз"),
            12,
        );

        assert_eq!(route.destination.prefix_len(), 32);
        assert_eq!(route.destination.addr(), address);
        assert!(
            route.gateway.is_some(),
            "маршрут мимо тоннеля идёт через шлюз"
        );
    }

    #[test]
    fn a_pinned_route_beats_the_default_halves() {
        let address: IpAddr = "203.0.113.10".parse().expect("адрес");
        let pinned = IpNet::from(address).prefix_len();
        for half in default_halves() {
            assert!(
                pinned > half.prefix_len(),
                "маршрут до сервера проигрывает {half}"
            );
        }
    }

    #[test]
    fn an_ipv6_server_is_not_pinned_through_an_ipv4_gateway() {
        let outside = DefaultRoute {
            interface_index: 4,
            address: "192.168.0.10".parse().expect("адрес"),
            gateway: "192.168.0.1".parse().expect("шлюз"),
            metric: 0,
        };
        let guard = RouteGuard::new();
        let server: IpAddr = "2001:db8::1".parse().expect("адрес");

        // Ничего не ставится и не падает: таблица маршрутов остаётся нетронутой.
        guard.pin_outside(&[server], &outside).expect("пропущен");
        assert!(guard.is_empty());
    }

    #[test]
    fn halves_cover_the_whole_space() {
        let halves = default_halves();
        assert_eq!(halves.len(), 2);
        assert!(halves.iter().all(|net| net.prefix_len() == 1));
    }

    #[test]
    fn guard_starts_empty() {
        let guard = RouteGuard::new();
        assert!(guard.is_empty());
        guard.restore().expect("снимать нечего");
    }

    #[test]
    fn route_via_interface_has_no_gateway() {
        let route = Route::via_interface("10.0.0.0/8".parse().expect("подсеть"), 7);
        assert!(route.gateway.is_none());
        assert_eq!(route.interface_index, 7);
    }
}
