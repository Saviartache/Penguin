//! `i2pd.conf`: только клиент, всё наружу — через обход TUN.

use std::net::SocketAddr;

/// HTTP-прокси i2pd; тот же адрес — умолчание `proxy` у протокола `i2p`.
pub const HTTP_PROXY: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 4444);

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
loglevel = warn
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
}
