//! Страна серверов по базе GeoIP: имя → адрес → код страны.
//!
//! Окно рисует по коду флаг и спрашивает об этом себя же (`AGENTS.md` §1.7):
//! база качается с GitHub, а имя сервера резолвится системным резолвером.
//! База лежит в каталоге пользователя: в общий каталог службы окну не писать.

use std::collections::BTreeMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use penguin_config::Paths;
use penguin_core::address::SocketAddress;
use penguin_match::address::GeoIpDatabase;

use crate::output::{Format, emit, table};

/// Выполняет команду: печатает страну каждого сервера, который удалось найти.
pub fn run(servers: &[String], format: Format) -> Result<()> {
    let path = Paths::user()
        .context("каталог данных пользователя неизвестен")?
        .geoip_file();
    ensure_database(&path)?;
    let database = GeoIpDatabase::open(&path).map_err(anyhow::Error::msg)?;

    let countries = locate(&database, servers);
    emit(format, &countries, render);
    Ok(())
}

/// Качает базу, если её нет или она устарела; устаревшая годится, пока сеть недоступна.
fn ensure_database(path: &Path) -> Result<()> {
    if !penguin_update::geoip::is_stale(path, SystemTime::now()) {
        return Ok(());
    }
    match penguin_update::geoip::download(path) {
        Ok(()) => Ok(()),
        Err(err) if path.exists() => {
            eprintln!("база GeoIP не обновлена, берётся прежняя: {err}");
            Ok(())
        }
        Err(err) => bail!("база GeoIP не скачана: {err}"),
    }
}

/// Страны серверов; резолвит параллельно — медленный DNS не множится на число серверов.
fn locate(database: &GeoIpDatabase, servers: &[String]) -> BTreeMap<String, String> {
    std::thread::scope(|scope| {
        let lookups: Vec<_> = servers
            .iter()
            .map(|server| scope.spawn(move || (server, address_of(server))))
            .collect();
        lookups
            .into_iter()
            .filter_map(|lookup| lookup.join().ok())
            .filter_map(|(server, ip)| Some((server.clone(), database.country_of(ip?)?)))
            .collect()
    })
}

/// Первый адрес сервера `хост:порт`; адрес без порта тоже годится.
fn address_of(server: &str) -> Option<IpAddr> {
    let address = SocketAddress::parse_or_port(server, 443).ok()?;
    if let Some(ip) = address.host.as_ip() {
        return Some(ip);
    }
    let host = address.host.as_domain()?;
    (host, address.port)
        .to_socket_addrs()
        .ok()?
        .next()
        .map(|socket| socket.ip())
}

fn render(countries: &BTreeMap<String, String>) -> String {
    let rows: Vec<Vec<String>> = countries
        .iter()
        .map(|(server, country)| vec![server.clone(), country.clone()])
        .collect();
    table(&["СЕРВЕР", "СТРАНА"], &rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_literal_needs_no_resolver() {
        assert_eq!(
            address_of("203.0.113.5:51820"),
            Some("203.0.113.5".parse().expect("адрес"))
        );
        assert_eq!(
            address_of("[2001:db8::1]:443"),
            Some("2001:db8::1".parse().expect("адрес"))
        );
        assert_eq!(
            address_of("203.0.113.5"),
            Some("203.0.113.5".parse().expect("адрес"))
        );
    }

    #[test]
    fn garbage_is_not_located() {
        assert_eq!(address_of(""), None);
        assert_eq!(address_of("host:notaport"), None);
    }
}
