//! `i2pd.conf`: только клиент, всё наружу — через обход TUN.

use std::net::SocketAddr;

/// HTTP-прокси i2pd; тот же адрес — умолчание `proxy` у протокола `i2p`.
pub const HTTP_PROXY: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 4444);

/// Узлы для первого запуска: серверы reseed в РФ заблокированы, GitHub — нет.
/// Файл кладёт в ветку `.github/workflows/i2p-reseed.yml`; raw-адрес отдаёт его
/// без перенаправления, по которому i2pd ходит по кругу.
pub const RESEED: &str =
    "https://raw.githubusercontent.com/Saviartache/penguin/i2p-reseed/i2pseeds.su3";

/// Настройки i2pd; `bypass` — SOCKS5 мимо тоннеля.
///
/// SSU2 выключен: через прокси i2pd возит его только по `UDP ASSOCIATE`, а NTCP2
/// хватает клиенту. Чужих туннелей не держим (`notransit`): за прокси входящих нет.
pub fn render(bypass: SocketAddr) -> String {
    let proxy = format!("socks://{bypass}");
    let port = HTTP_PROXY.port();
    format!(
        "\
log = file
# Ход reseed пишется на info; журнал служба заводит заново на каждый запуск.
loglevel = info
ipv4 = true
ipv6 = false
notransit = true

[http]
enabled = false

[httpproxy]
enabled = true
address = 127.0.0.1
port = {port}
addresshelper = false

[socksproxy]
enabled = false

[sam]
enabled = false

[ntcp2]
enabled = true
published = false
proxy = {proxy}

[ssu2]
enabled = false

[upnp]
enabled = false

[reseed]
file = {RESEED}
proxy = {proxy}

[addressbook]
enabled = false
"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_way_out_goes_through_the_bypass() {
        let conf = render("127.0.0.1:50123".parse().expect("адрес"));
        assert_eq!(conf.matches("proxy = socks://127.0.0.1:50123\n").count(), 2);
        assert!(conf.contains("[ssu2]\nenabled = false"));
        assert!(conf.contains("port = 4444"));
    }

    #[test]
    fn nodes_come_from_this_repository() {
        let path = env!("CARGO_PKG_REPOSITORY").trim_start_matches("https://github.com/");
        assert_eq!(
            RESEED,
            format!("https://raw.githubusercontent.com/{path}/i2p-reseed/i2pseeds.su3")
        );
        assert!(
            render("127.0.0.1:1".parse().expect("адрес")).contains(&format!("file = {RESEED}\n"))
        );
    }
}
