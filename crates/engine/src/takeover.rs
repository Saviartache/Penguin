//! Перехват соединений, открытых до тоннеля: без сброса они живут мимо него, пока приложение
//! само не откроет новое. Сброшенное приложение переподключается сразу — уже через тоннель.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

/// Уйдёт ли теперь соединение в тоннель: он забирает весь IPv4 двумя половинами, кроме
/// сервера (выведен наружу) и адресов, до которых ведут маршруты точнее (локальная сеть).
pub fn moves_into_tunnel(remote: SocketAddrV4, pinned: &[IpAddr]) -> bool {
    let ip = *remote.ip();
    global(ip) && !pinned.contains(&IpAddr::V4(ip))
}

/// Адрес из интернета, а не служебный, частный или подставной.
fn global(ip: Ipv4Addr) -> bool {
    let [first, second, ..] = ip.octets();
    let shared = first == 100 && (64..128).contains(&second);
    // 198.18.0.0/15 — подставные адреса fake-IP.
    let benchmarking = first == 198 && (18..20).contains(&second);
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || shared
        || benchmarking)
}

/// Сбрасывает соединения, которые теперь пошли бы через тоннель.
pub async fn take_over(pinned: Vec<IpAddr>) {
    let reset = tokio::task::spawn_blocking(move || {
        penguin_platform::sockets::reset_tcp(&|remote| moves_into_tunnel(remote, &pinned))
    })
    .await;

    match reset {
        Ok(Ok(0)) => {}
        Ok(Ok(count)) => tracing::info!(count, "соединения, открытые до тоннеля, пересоздаются"),
        // Не беда: стек тоннеля сбросит такое соединение на первом же пакете.
        Ok(Err(err)) => tracing::warn!(%err, "соединения, открытые до тоннеля, не сброшены"),
        Err(err) => tracing::warn!(%err, "сброс соединений прерван"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(address: &str) -> SocketAddrV4 {
        address.parse().expect("адрес")
    }

    #[test]
    fn an_internet_connection_moves_into_the_tunnel() {
        assert!(moves_into_tunnel(remote("93.184.216.34:443"), &[]));
    }

    #[test]
    fn the_server_itself_stays_outside() {
        let server: IpAddr = "93.184.216.34".parse().expect("адрес");
        assert!(!moves_into_tunnel(remote("93.184.216.34:443"), &[server]));
    }

    #[test]
    fn local_and_service_addresses_are_left_alone() {
        for address in [
            "192.168.1.10:22",
            "10.0.0.5:445",
            "172.16.0.1:80",
            "127.0.0.1:8080",
            "169.254.1.1:80",
            "100.64.0.1:443",
            "198.18.0.7:443",
            "224.0.0.251:5353",
        ] {
            assert!(!moves_into_tunnel(remote(address), &[]), "{address}");
        }
    }
}
