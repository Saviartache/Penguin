//! Следы прошлого запуска: что убрать при подъёме после аварии (запрет трафика, адаптер, DNS).
//!
//! Ошибки пишутся в журнал, а не возвращаются: шаги независимы, служба обязана подняться.

use std::net::Ipv4Addr;

/// Убирает всё, что мог оставить убитый прошлый запуск; `tunnel` — адрес адаптера из настроек.
pub fn recover(tunnel: Ipv4Addr) {
    if let Err(err) = crate::firewall::recover_leftovers() {
        tracing::error!(%err, "не снят запрет, оставшийся от прошлого запуска");
    }

    // DNS раньше адаптера: подмена мешает узнать адрес сервера, даже если адаптер не уберётся.
    if let Err(err) = crate::dns_settings::recover_leftovers() {
        tracing::error!(%err, "не возвращены настройки DNS прошлого запуска");
    }

    if let Err(err) = shut_down_tunnel(tunnel) {
        tracing::error!(%err, "не убран адаптер, оставшийся от прошлого запуска");
    }

    // Последним: путь наружу мог пропасть вместе с адаптером.
    if let Err(err) = restore_default_route() {
        tracing::error!(%err, "не возвращён маршрут по умолчанию");
    }
}

/// Гасит (не удаляет: `utun` живёт, пока открыт дескриптор) адаптер тоннеля прошлого запуска.
#[cfg(unix)]
fn shut_down_tunnel(tunnel: Ipv4Addr) -> crate::error::PlatformResult<()> {
    let Some(name) = interface_with(tunnel)? else {
        return Ok(());
    };

    tracing::warn!(
        interface = %name,
        %tunnel,
        "от прошлого запуска остался адаптер тоннеля — гашу"
    );
    down(&name)
}

/// Возвращает путь наружу: после убитого тоннеля macOS оставляет единственный маршрут с флагом
/// `IFSCOPE`, и обычный сокет по нему не выходит.
#[cfg(target_os = "macos")]
fn restore_default_route() -> crate::error::PlatformResult<()> {
    let table =
        crate::command::run("/usr/sbin/netstat", &["-rn", "-f", "inet"]).map_err(|err| {
            err.into_error(crate::error::PlatformError::Interface, "таблица маршрутов")
        })?;

    let Some(gateway) = orphaned_gateway(&table) else {
        return Ok(());
    };

    tracing::warn!(%gateway, "маршрут наружу остался привязан к интерфейсу — возвращаю общий");
    crate::command::run("/sbin/route", &["-n", "add", "default", &gateway])
        .map(|_| ())
        .map_err(|err| err.into_error(crate::error::PlatformError::Interface, "маршрут наружу"))
}

/// Шлюз осиротевшего маршрута: `Some`, только если маршруты по умолчанию есть и все привязаны (`I`).
#[cfg(target_os = "macos")]
fn orphaned_gateway(table: &str) -> Option<String> {
    let mut scoped = None;

    for line in table.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("default") {
            continue;
        }
        let gateway = fields.next()?;
        let flags = fields.next().unwrap_or_default();

        // `I` — `RTF_IFSCOPE`; строчная `i` (`RTF_IFREF`) — другое.
        if !flags.contains('I') {
            return None;
        }
        // Шлюз-имя интерфейса (`link#24`) повторить нечем.
        if scoped.is_none() && gateway.parse::<std::net::IpAddr>().is_ok() {
            scoped = Some(gateway.to_owned());
        }
    }

    scoped
}

/// На Linux тоннель ставит свой маршрут с меньшей метрикой, физический остаётся.
#[cfg(target_os = "linux")]
fn restore_default_route() -> crate::error::PlatformResult<()> {
    Ok(())
}

/// Имя интерфейса с этим адресом.
#[cfg(unix)]
fn interface_with(address: Ipv4Addr) -> crate::error::PlatformResult<Option<String>> {
    use crate::error::PlatformError;

    let addresses = nix::ifaddrs::getifaddrs()
        .map_err(|err| PlatformError::Interface(format!("список интерфейсов: {err}")))?;

    for interface in addresses {
        let Some(storage) = interface.address else {
            continue;
        };
        let Some(inet) = storage.as_sockaddr_in() else {
            continue;
        };
        if inet.ip() == address {
            return Ok(Some(interface.interface_name));
        }
    }
    Ok(None)
}

/// Опускает интерфейс.
#[cfg(target_os = "macos")]
fn down(name: &str) -> crate::error::PlatformResult<()> {
    crate::command::run("/sbin/ifconfig", &[name, "down"])
        .map(|_| ())
        .map_err(|err| err.into_error(crate::error::PlatformError::Interface, "адаптер тоннеля"))
}

/// Опускает интерфейс.
#[cfg(target_os = "linux")]
fn down(name: &str) -> crate::error::PlatformResult<()> {
    crate::command::run("ip", &["link", "set", name, "down"])
        .map(|_| ())
        .map_err(|err| err.into_error(crate::error::PlatformError::Interface, "адаптер тоннеля"))
}

/// На Windows адаптер убирает драйвер Wintun вместе с процессом.
#[cfg(windows)]
fn shut_down_tunnel(tunnel: Ipv4Addr) -> crate::error::PlatformResult<()> {
    let _ = tunnel;
    Ok(())
}

/// На Windows маршрут к интерфейсу не привязывается; с адаптером исчезает и маршрут тоннеля.
#[cfg(windows)]
fn restore_default_route() -> crate::error::PlatformResult<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_loopback_is_found_by_its_address() {
        let found = interface_with(Ipv4Addr::LOCALHOST).expect("список читается");
        assert!(found.is_some(), "петля не найдена по своему адресу");
    }

    #[test]
    fn an_address_nobody_has_finds_nothing() {
        // Адрес из RFC 5737 не назначают.
        let found = interface_with(Ipv4Addr::new(192, 0, 2, 1)).expect("список читается");
        assert_eq!(found, None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_machine_with_a_general_route_is_left_alone() {
        let table = "Routing tables\n\
             \n\
             Internet:\n\
             Destination        Gateway            Flags        Netif Expire\n\
             default            192.168.0.1        UGSc           en0\n\
             127                127.0.0.1          UCS            lo0\n";
        assert_eq!(orphaned_gateway(table), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_route_left_bound_to_an_interface_is_repaired() {
        let table = "Routing tables\n\
             \n\
             Internet:\n\
             Destination        Gateway            Flags        Netif Expire\n\
             default            192.168.0.1        UGScIg         en0\n\
             127                127.0.0.1          UCS            lo0\n";
        assert_eq!(orphaned_gateway(table), Some("192.168.0.1".to_owned()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn one_general_route_among_bound_ones_is_enough() {
        let table = "Destination        Gateway            Flags        Netif\n\
             default            link#24            UCSg           utun8\n\
             default            192.168.0.1        UGScIg         en0\n";
        assert_eq!(orphaned_gateway(table), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_table_without_a_default_route_is_not_our_business() {
        let table = "Destination        Gateway            Flags        Netif\n\
             127                127.0.0.1          UCS            lo0\n";
        assert_eq!(orphaned_gateway(table), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_interface_route_gives_nothing_to_repeat() {
        let table = "Destination        Gateway            Flags        Netif\n\
             default            link#24            UCSgI          utun8\n";
        assert_eq!(orphaned_gateway(table), None);
    }

    #[test]
    fn recovering_on_a_clean_machine_does_nothing_and_says_nothing() {
        shut_down_tunnel(Ipv4Addr::new(192, 0, 2, 1)).expect("чистая машина — не ошибка");
    }
}
