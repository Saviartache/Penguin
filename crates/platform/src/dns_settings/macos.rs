//! macOS: `networksetup`. DNS подменяется у всех сетевых служб (utun службой не считается, а
//! резолвер спрашивает серверы Wi-Fi и Ethernet напрямую); прежние значения — в файле, не в памяти.

use std::fmt::Write;
use std::net::IpAddr;
use std::path::Path;

use crate::command;
use crate::error::{PlatformError, PlatformResult};

/// Программа, которой правятся настройки сетевых служб.
const NETWORKSETUP: &str = "/usr/sbin/networksetup";

/// Куда сохраняются прежние значения.
const BACKUP: &str = "/var/db/penguin/dns.backup";

/// Слово `networksetup` для «вернуться к DHCP».
const EMPTY: &str = "Empty";

/// Объявляет адрес единственным DNS у всех сетевых служб.
pub fn set(server: IpAddr) -> PlatformResult<()> {
    let services = services()?;
    if services.is_empty() {
        return Err(PlatformError::DnsSettings(
            "система не назвала ни одной сетевой службы".to_owned(),
        ));
    }

    // Сохранять до первой правки, иначе сохранится собственная подмена.
    if !Path::new(BACKUP).exists() {
        save(&services)?;
    }

    for service in &services {
        command::run(
            NETWORKSETUP,
            &["-setdnsservers", service, &server.to_string()],
        )
        .map_err(|err| err.into_error(PlatformError::DnsSettings, "настройки DNS"))?;
    }
    Ok(())
}

/// Возвращает настройки, какими они были.
pub fn reset() -> PlatformResult<()> {
    let Ok(saved) = std::fs::read_to_string(BACKUP) else {
        return Ok(());
    };

    let mut first_error = None;
    for (service, servers) in parse(&saved) {
        let mut arguments = vec!["-setdnsservers", service];
        arguments.extend(servers.iter().copied());

        if let Err(err) = command::run(NETWORKSETUP, &arguments) {
            let err = err.into_error(PlatformError::DnsSettings, "настройки DNS");
            tracing::error!(service, %err, "настройки DNS не восстановлены");
            first_error.get_or_insert(err);
        }
    }

    // Файл остаётся после ошибки: восстановление повторится при следующем запуске службы.
    if first_error.is_none() {
        let _ = std::fs::remove_file(BACKUP);
    }

    first_error.map_or(Ok(()), Err)
}

/// Сохраняет текущие значения.
fn save(services: &[String]) -> PlatformResult<()> {
    let mut text = String::new();
    for service in services {
        let current = command::run(NETWORKSETUP, &["-getdnsservers", service])
            .map_err(|err| err.into_error(PlatformError::DnsSettings, "настройки DNS"))?;
        let _ = writeln!(text, "{service}\t{}", addresses(&current).join(" "));
    }

    if let Some(parent) = Path::new(BACKUP).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| PlatformError::DnsSettings(format!("{}: {err}", parent.display())))?;
    }
    std::fs::write(BACKUP, text)
        .map_err(|err| PlatformError::DnsSettings(format!("{BACKUP}: {err}")))
}

/// Список сетевых служб машины.
fn services() -> PlatformResult<Vec<String>> {
    let output = command::run(NETWORKSETUP, &["-listallnetworkservices"])
        .map_err(|err| err.into_error(PlatformError::DnsSettings, "настройки DNS"))?;
    Ok(service_names(&output))
}

/// Имена служб из вывода `networksetup`: первая строка (пояснение, переводится) пропускается по
/// месту, отключённые (со звёздочкой) — не берутся.
fn service_names(output: &str) -> Vec<String> {
    output
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('*'))
        .map(str::to_owned)
        .collect()
}

/// Адреса из вывода `-getdnsservers`; фраза «серверов нет» на языке системы адресом не разберётся.
fn addresses(output: &str) -> Vec<&str> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| line.parse::<IpAddr>().is_ok())
        .collect()
}

/// Разбирает сохранённые значения; пустой список заменяется словом «вернуть DHCP».
fn parse(saved: &str) -> Vec<(&str, Vec<&str>)> {
    saved
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(service, servers)| {
            let servers: Vec<&str> = servers.split_whitespace().collect();
            let servers = if servers.is_empty() {
                vec![EMPTY]
            } else {
                servers
            };
            (service, servers)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_explanatory_line_is_not_a_service() {
        let output =
            "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nEthernet\n";
        assert_eq!(service_names(output), vec!["Wi-Fi", "Ethernet"]);
    }

    #[test]
    fn a_disabled_service_is_skipped() {
        let output = "Пояснение\n*Bluetooth PAN\nWi-Fi\n";
        assert_eq!(service_names(output), vec!["Wi-Fi"]);
    }

    #[test]
    fn only_addresses_count_as_servers() {
        assert_eq!(
            addresses("192.168.0.1\n1.1.1.1\n"),
            vec!["192.168.0.1", "1.1.1.1"]
        );
        assert!(addresses("There aren't any DNS Servers set on Wi-Fi.\n").is_empty());
        assert!(addresses("Для сети Wi-Fi серверы DNS не заданы.\n").is_empty());
    }

    #[test]
    fn a_service_without_servers_goes_back_to_dhcp() {
        let parsed = parse("Wi-Fi\t\nEthernet\t1.1.1.1 8.8.8.8\n");
        assert_eq!(parsed[0], ("Wi-Fi", vec![EMPTY]));
        assert_eq!(parsed[1], ("Ethernet", vec!["1.1.1.1", "8.8.8.8"]));
    }

    #[test]
    fn a_service_name_with_spaces_survives() {
        let parsed = parse("USB 10/100 LAN\t9.9.9.9\n");
        assert_eq!(parsed[0].0, "USB 10/100 LAN");
    }
}
