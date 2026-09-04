//! macOS: `networksetup`.
//!
//! Подменяется DNS **не** у адаптера тоннеля, а у всех сетевых служб машины.
//! Причина в устройстве системы: utun сетевой службой не считается, настроек
//! DNS у него нет, а резолвер спрашивает серверы, прописанные у Wi-Fi и
//! Ethernet, — и спрашивает их напрямую, минуя таблицу маршрутизации.
//!
//! Прежние значения сохраняются в файл, а не в память: подменённый DNS
//! переживает падение клиента, и вернуть его тогда будет неоткуда.

use std::net::IpAddr;
use std::path::Path;

use crate::command;
use crate::error::{PlatformError, PlatformResult};

/// Программа, которой правятся настройки сетевых служб.
const NETWORKSETUP: &str = "/usr/sbin/networksetup";

/// Куда сохраняются прежние значения.
const BACKUP: &str = "/var/db/penguin/dns.backup";

/// Что писать вместо списка серверов, когда своих у службы не было.
///
/// Слово понимает сама `networksetup`; оно означает «вернуться к тому, что
/// выдаёт DHCP».
const EMPTY: &str = "Empty";

/// Объявляет адрес единственным DNS у всех сетевых служб.
pub fn set(server: IpAddr) -> PlatformResult<()> {
    let services = services()?;
    if services.is_empty() {
        return Err(PlatformError::DnsSettings(
            "система не назвала ни одной сетевой службы".to_owned(),
        ));
    }

    // Прежние значения сохраняются до первой правки: сохранив их после, мы
    // сохранили бы собственную подмену.
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
        // Сохранённого нет — значит, и подменять было нечего.
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

    // Файл убирается только после успеха: оставшись, он позволит повторить
    // восстановление при следующем запуске службы.
    if first_error.is_none() {
        let _ = std::fs::remove_file(BACKUP);
    }

    match first_error {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// Сохраняет текущие значения.
fn save(services: &[String]) -> PlatformResult<()> {
    let mut text = String::new();
    for service in services {
        let current = command::run(NETWORKSETUP, &["-getdnsservers", service])
            .map_err(|err| err.into_error(PlatformError::DnsSettings, "настройки DNS"))?;
        text.push_str(&format!("{service}\t{}\n", addresses(&current).join(" ")));
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

/// Имена служб из вывода `networksetup`.
///
/// Первая строка — пояснение для человека, и пропускается она по месту, а не
/// по содержимому: текст пояснения переводится вместе с системой.
/// Отключённые службы помечены звёздочкой и в список не идут: их настройки
/// всё равно ни на что не влияют.
fn service_names(output: &str) -> Vec<String> {
    output
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('*'))
        .map(str::to_owned)
        .collect()
}

/// Адреса из вывода `networksetup -getdnsservers`.
///
/// Отбираются те строки, которые разбираются как адрес. Служба без своих
/// серверов отвечает предложением на языке системы — и оно, в отличие от
/// адреса, не разберётся ни на каком.
fn addresses(output: &str) -> Vec<&str> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| line.parse::<IpAddr>().is_ok())
        .collect()
}

/// Разбирает сохранённые значения.
fn parse(saved: &str) -> Vec<(&str, Vec<&str>)> {
    saved
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(service, servers)| {
            let servers: Vec<&str> = servers.split_whitespace().collect();
            // Пустой список означает «своих серверов не было»: вернуть надо
            // не пустоту, а признак «спрашивать DHCP».
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
        // Текст пояснения переводится вместе с системой, поэтому первая
        // строка пропускается по месту, а не по содержимому.
        let output =
            "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nEthernet\n";
        assert_eq!(service_names(output), vec!["Wi-Fi", "Ethernet"]);
    }

    #[test]
    fn a_disabled_service_is_skipped() {
        // Её настройки ни на что не влияют, а правка вернёт отказ.
        let output = "Пояснение\n*Bluetooth PAN\nWi-Fi\n";
        assert_eq!(service_names(output), vec!["Wi-Fi"]);
    }

    #[test]
    fn only_addresses_count_as_servers() {
        // Служба без своих серверов отвечает предложением на языке системы;
        // принять его за адрес значит записать в настройки мусор.
        assert_eq!(
            addresses("192.168.0.1\n1.1.1.1\n"),
            vec!["192.168.0.1", "1.1.1.1"]
        );
        assert!(addresses("There aren't any DNS Servers set on Wi-Fi.\n").is_empty());
        assert!(addresses("Для сети Wi-Fi серверы DNS не заданы.\n").is_empty());
    }

    #[test]
    fn a_service_without_servers_goes_back_to_dhcp() {
        // Пустой список нельзя передать как есть: `networksetup` ждёт слова.
        let parsed = parse("Wi-Fi\t\nEthernet\t1.1.1.1 8.8.8.8\n");
        assert_eq!(parsed[0], ("Wi-Fi", vec![EMPTY]));
        assert_eq!(parsed[1], ("Ethernet", vec!["1.1.1.1", "8.8.8.8"]));
    }

    #[test]
    fn a_service_name_with_spaces_survives() {
        // «Wi-Fi» и «USB 10/100 LAN» — обычные имена служб; разделять их
        // пробелом было бы ошибкой.
        let parsed = parse("USB 10/100 LAN\t9.9.9.9\n");
        assert_eq!(parsed[0].0, "USB 10/100 LAN");
    }
}
