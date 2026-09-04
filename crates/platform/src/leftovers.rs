//! Следы прошлого запуска: что убрать, поднимаясь после аварии.
//!
//! Демона убивают. `kill -9`, паника, пропавшее питание, остановка службы, не
//! успевшей откатиться, — и каждый такой случай оставляет машину в состоянии,
//! из которого она сама не выйдет:
//!
//! | След | Чем это для человека |
//! |---|---|
//! | запрет исходящего трафика | сети нет вовсе, и переживает перезагрузку |
//! | поднятый адаптер тоннеля | маршрут наружу ведёт в никуда |
//! | подменённый DNS | имена разрешаются в подставные адреса |
//!
//! Последние два опаснее всего тем, что бьют по самому клиенту: следующий
//! запуск не может ни узнать адрес своего сервера, ни достучаться до него, —
//! и сколько его ни перезапускай, он будет говорить «рукопожатие не
//! завершилось». Выйти из этого круга можно только здесь, до первого
//! подключения.
//!
//! Ошибки наружу не отдаются, а пишутся в журнал. Шаги независимы, неудача
//! одного не повод не делать остальные, а служба обязана подняться в любом
//! случае: она единственное, чем это чинится.

use std::net::Ipv4Addr;

/// Убирает всё, что мог оставить после себя убитый прошлый запуск.
///
/// `tunnel` — адрес адаптера тоннеля из настроек. По нему и опознаётся свой
/// адаптер: имя система может дать любое (`utun8`, `utun3`), а адрес задаём
/// мы.
pub fn recover(tunnel: Ipv4Addr) {
    if let Err(err) = crate::firewall::recover_leftovers() {
        tracing::error!(%err, "не снят запрет, оставшийся от прошлого запуска");
    }

    // DNS раньше адаптера: подмена — это то, что мешает клиенту узнать адрес
    // своего сервера, и снимать её надо в любом случае, даже если адаптер
    // убрать не удастся.
    if let Err(err) = crate::dns_settings::recover_leftovers() {
        tracing::error!(%err, "не возвращены настройки DNS прошлого запуска");
    }

    if let Err(err) = shut_down_tunnel(tunnel) {
        tracing::error!(%err, "не убран адаптер, оставшийся от прошлого запуска");
    }

    // Последним и обязательно после адаптера: путь наружу мог пропасть вместе
    // с ним.
    if let Err(err) = restore_default_route() {
        tracing::error!(%err, "не возвращён маршрут по умолчанию");
    }
}

/// Гасит адаптер тоннеля, оставшийся от прошлого запуска.
///
/// Гасит, а не удаляет: `utun` в macOS живёт, пока открыт его дескриптор, и
/// удалять его снаружи нечем. Погашенный интерфейс система убирает из таблицы
/// маршрутизации сама — а именно маршруты и мешают.
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

/// Возвращает машине путь наружу, если он пропал вместе с адаптером.
///
/// macOS, поднимая тоннель, физический маршрут по умолчанию не убирает, а
/// **привязывает к интерфейсу** — флаг `IFSCOPE`, буква `I` в таблице. Пока
/// тоннель есть, наружу ходят через него, и всё в порядке. Когда он исчезает
/// не по-хорошему, у машины остаётся один привязанный маршрут — а по нему
/// обычный сокет наружу не выйдет: система отвечает «нет такого маршрута».
///
/// Снаружи это выглядит страшнее, чем есть: сеть жива, Wi-Fi подключён, а не
/// работает ничего — ни одно имя не разрешается, ни одно соединение не
/// открывается. Связать это с VPN, который уже закрыт, человек не может.
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

/// Шлюз, до которого машине больше не дойти, — или `None`, если всё в порядке.
///
/// Свободная функция с тестом: ошибка здесь означает либо машину, оставшуюся
/// без сети, либо лишний маршрут, дописанный на ровном месте.
///
/// Ответ `Some` только тогда, когда маршруты по умолчанию есть и **все** они
/// привязаны к интерфейсу. Хотя бы один общий — и чинить нечего.
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

        // `I` — это `RTF_IFSCOPE`: маршрут виден только трафику, привязанному
        // к тому же интерфейсу. Строчная `i` рядом значит другое (`RTF_IFREF`),
        // и путать их нельзя.
        if !flags.contains('I') {
            return None;
        }
        // Шлюзом может стоять и имя интерфейса (`link#24`) — такой маршрут
        // повторить нечем.
        if scoped.is_none() && gateway.parse::<std::net::IpAddr>().is_ok() {
            scoped = Some(gateway.to_owned());
        }
    }

    scoped
}

/// На Linux привязанных к интерфейсу маршрутов по умолчанию нет: тоннель
/// ставит свой с меньшей метрикой, и физический никуда не девается.
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
        if Ipv4Addr::from(inet.ip()) == address {
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

/// Гасит адаптер тоннеля, оставшийся от прошлого запуска.
///
/// На Windows таких не бывает: адаптер заводит драйвер Wintun и он же убирает
/// его, как только процесс, открывший сеанс, исчезает, — хоть по своей воле,
/// хоть нет.
#[cfg(windows)]
fn shut_down_tunnel(tunnel: Ipv4Addr) -> crate::error::PlatformResult<()> {
    let _ = tunnel;
    Ok(())
}

/// На Windows маршрут по умолчанию к интерфейсу не привязывается: тоннель
/// соперничает с физическим метрикой, и с исчезновением адаптера побеждает
/// физический.
#[cfg(windows)]
fn restore_default_route() -> crate::error::PlatformResult<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_loopback_is_found_by_its_address() {
        // Опознание идёт по адресу, а не по имени: имя адаптеру даёт система, и
        // угадывать его нельзя. Петля есть на любой машине и адрес у неё
        // известен — на ней и проверяется, что поиск работает.
        let found = interface_with(Ipv4Addr::LOCALHOST).expect("список читается");
        assert!(found.is_some(), "петля не найдена по своему адресу");
    }

    #[test]
    fn an_address_nobody_has_finds_nothing() {
        // Иначе служба гасила бы на старте чужой интерфейс. Адрес — из подсети
        // для документации (RFC 5737), её не назначают.
        let found = interface_with(Ipv4Addr::new(192, 0, 2, 1)).expect("список читается");
        assert_eq!(found, None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_machine_with_a_general_route_is_left_alone() {
        // Обычная таблица здоровой машины. Дописать в неё маршрут значило бы
        // чинить то, что не сломано.
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
        // Так выглядит машина после убитого тоннеля: маршрут остался, но
        // привязан к интерфейсу (`I`), и наружу по нему обычный сокет не
        // выйдет. Именно это состояние снаружи выглядит как «сети нет вовсе».
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
        // Пока хотя бы один маршрут не привязан, машина наружу выходит.
        let table = "Destination        Gateway            Flags        Netif\n\
             default            link#24            UCSg           utun8\n\
             default            192.168.0.1        UGScIg         en0\n";
        assert_eq!(orphaned_gateway(table), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_table_without_a_default_route_is_not_our_business() {
        // Машины без маршрута наружу бывают — например, без сети вообще.
        // Выдумывать ей шлюз мы не станем.
        let table = "Destination        Gateway            Flags        Netif\n\
             127                127.0.0.1          UCS            lo0\n";
        assert_eq!(orphaned_gateway(table), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_interface_route_gives_nothing_to_repeat() {
        // Шлюзом стоит имя интерфейса, а не адрес: повторить такой маршрут
        // нечем, и выдумывать адрес нельзя.
        let table = "Destination        Gateway            Flags        Netif\n\
             default            link#24            UCSgI          utun8\n";
        assert_eq!(orphaned_gateway(table), None);
    }

    #[test]
    fn recovering_on_a_clean_machine_does_nothing_and_says_nothing() {
        // Вызывается при каждом запуске службы, в том числе на машине без
        // единого следа. Упасть здесь означало бы не подняться вовсе.
        shut_down_tunnel(Ipv4Addr::new(192, 0, 2, 1)).expect("чистая машина — не ошибка");
    }
}
