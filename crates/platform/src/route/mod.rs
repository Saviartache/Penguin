//! Управление таблицей маршрутизации.
//!
//! Тоннель забирает трафик не сам по себе: система должна решить отдавать его
//! в TUN, а решает она это маршрутом. Отсюда две обязанности крейта —
//! поставить маршруты и **гарантированно** их снять.
//!
//! Вторая важнее первой. Маршрут, оставшийся от упавшего клиента, ведёт в
//! адаптер, которого больше нет, и сеть у пользователя не работает вовсе —
//! причём он не поймёт почему. Поэтому все поставленные маршруты
//! запоминаются, а снятие идёт даже по аварийному пути.

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
    /// Через какой узел. `None` — маршрут «на интерфейс»: за TUN никого нет.
    pub gateway: Option<IpAddr>,
    /// Через какой интерфейс.
    pub interface_index: u32,
    /// Метрика. `None` — самая предпочтительная.
    pub metric: Option<u32>,
}

impl Route {
    /// Маршрут на интерфейс.
    pub fn via_interface(destination: IpNet, interface_index: u32) -> Self {
        Self {
            destination,
            gateway: None,
            interface_index,
            metric: None,
        }
    }

    /// Маршрут через шлюз.
    pub fn via_gateway(destination: IpNet, gateway: IpAddr, interface_index: u32) -> Self {
        Self {
            destination,
            gateway: Some(gateway),
            interface_index,
            metric: None,
        }
    }
}

/// Маршруты, поставленные клиентом.
///
/// Всё, что поставлено, записывается сюда — и снимается отсюда же при
/// остановке. Держать список в голове нельзя: клиент может упасть между
/// постановкой первого и второго маршрута.
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

    /// Проводит адреса **мимо** тоннеля — тем путём, которым машина выходила
    /// наружу до его подъёма.
    ///
    /// Без этого тоннель разговаривает сам с собой. Маршруты по умолчанию
    /// заворачивают в адаптер всё подряд, включая пакеты до самого сервера:
    /// они уходят в тоннель, попадают в собственный стек, отправляются наружу
    /// — и снова заворачиваются. Снаружи это выглядит как «подключено, но не
    /// работает даже проверка задержки».
    ///
    /// Хватает длины префикса: у адреса узла она наибольшая, и система
    /// выбирает такой маршрут раньше любого другого.
    pub fn pin_outside(&self, addresses: &[IpAddr], outside: &DefaultRoute) -> PlatformResult<()> {
        for address in addresses {
            self.add(Route::via_gateway(
                IpNet::from(*address),
                outside.gateway,
                outside.interface_index,
            ))?;
        }
        Ok(())
    }

    /// Заворачивает весь трафик в интерфейс.
    ///
    /// Двумя половинами вместо `0.0.0.0/0`: их префикс длиннее, и система
    /// выбирает их раньше любого маршрута по умолчанию — включая чужой
    /// VPN-клиент, который тоже прописал себе метрику поменьше.
    pub fn capture_all(&self, interface_index: u32) -> PlatformResult<()> {
        for half in default_halves() {
            self.add(Route::via_interface(half, interface_index))?;
        }
        Ok(())
    }

    /// Снимает всё поставленное.
    ///
    /// Продолжает даже после ошибки: неснятый маршрут номер один не повод
    /// оставить в системе ещё и номер два. Возвращает первую ошибку.
    pub fn restore(&self) -> PlatformResult<()> {
        let routes = std::mem::take(&mut *self.installed.lock());
        let mut first_error = None;

        for route in routes.iter().rev() {
            if let Err(err) = remove_route(route) {
                tracing::error!(destination = %route.destination, %err, "маршрут не снят");
                first_error.get_or_insert(err);
            }
        }

        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
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
        // Последняя линия обороны. Маршрут, оставшийся от упавшего клиента,
        // ведёт в несуществующий адаптер, и сеть не работает вовсе.
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
        // Длина префикса и решает: у адреса узла она наибольшая, и система
        // выбирает такой маршрут раньше маршрута по умолчанию — в том числе
        // раньше нашего собственного.
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
        // Иначе пакет до сервера уйдёт в тоннель, и тоннель заглушит сам себя.
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
    fn halves_cover_the_whole_space() {
        let halves = default_halves();
        assert_eq!(halves.len(), 2);
        assert!(halves.iter().all(|net| net.prefix_len() == 1));
    }

    #[test]
    fn guard_starts_empty() {
        let guard = RouteGuard::new();
        assert!(guard.is_empty());
        // Пустой список — не повод считать откат неудавшимся.
        guard.restore().expect("снимать нечего");
    }

    #[test]
    fn route_via_interface_has_no_gateway() {
        // За TUN никого нет: следующего узла не существует.
        let route = Route::via_interface("10.0.0.0/8".parse().expect("подсеть"), 7);
        assert!(route.gateway.is_none());
        assert_eq!(route.interface_index, 7);
    }
}
