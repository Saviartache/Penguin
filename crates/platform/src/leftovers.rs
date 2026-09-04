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

    #[test]
    fn recovering_on_a_clean_machine_does_nothing_and_says_nothing() {
        // Вызывается при каждом запуске службы, в том числе на машине без
        // единого следа. Упасть здесь означало бы не подняться вовсе.
        shut_down_tunnel(Ipv4Addr::new(192, 0, 2, 1)).expect("чистая машина — не ошибка");
    }
}
