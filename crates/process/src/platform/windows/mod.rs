//! Windows: таблицы соединений IP Helper и путь по pid. Снимок таблицы живёт
//! 500 мс: дольше врёт, короче дорого.

pub mod icon;
pub mod path;
pub mod table;
pub mod tcp_table;
pub mod udp_table;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use penguin_core::network::Network;

use self::table::Entry;
use crate::cache::IdentityCache;
use crate::identity::ProcessIdentity;
use crate::resolver::FlowOwnerResolver;

/// Сколько живёт снимок таблицы.
const SNAPSHOT_TTL: Duration = Duration::from_millis(500);

/// Поиск владельца соединения в Windows.
#[derive(Debug)]
pub struct WindowsResolver {
    tcp: Mutex<Snapshot>,
    udp: Mutex<Snapshot>,
    identities: IdentityCache,
}

#[derive(Debug)]
struct Snapshot {
    entries: Vec<Entry>,
    taken: Option<Instant>,
}

impl Snapshot {
    const fn empty() -> Self {
        Self {
            entries: Vec::new(),
            taken: None,
        }
    }

    fn is_fresh(&self, now: Instant) -> bool {
        self.taken
            .is_some_and(|taken| now.duration_since(taken) < SNAPSHOT_TTL)
    }

    fn refresh(&mut self, network: Network) {
        self.entries = match network {
            Network::Tcp => tcp_table::snapshot(),
            Network::Udp => udp_table::snapshot(),
        };
        self.taken = Some(Instant::now());
    }
}

impl WindowsResolver {
    /// Создаёт резолвер.
    pub fn new() -> Self {
        Self {
            tcp: Mutex::new(Snapshot::empty()),
            udp: Mutex::new(Snapshot::empty()),
            identities: IdentityCache::new(),
        }
    }

    /// Номер процесса-владельца; при промахе по несвежему снимку таблица перечитывается один раз.
    fn pid_of(&self, network: Network, local: SocketAddr) -> Option<u32> {
        let slot = match network {
            Network::Tcp => &self.tcp,
            Network::Udp => &self.udp,
        };

        let mut snapshot = slot.lock();
        let was_stale = !snapshot.is_fresh(Instant::now());
        if was_stale {
            snapshot.refresh(network);
        }

        if let Some(pid) = find(&snapshot.entries, local) {
            return Some(pid);
        }
        if was_stale {
            return None;
        }

        snapshot.refresh(network);
        find(&snapshot.entries, local)
    }
}

/// Ищет запись: точный адрес, затем порт сокета на `0.0.0.0`/`[::]` того же семейства.
fn find(entries: &[Entry], local: SocketAddr) -> Option<u32> {
    if let Some(entry) = entries.iter().find(|entry| entry.local == local) {
        return Some(entry.pid);
    }

    entries
        .iter()
        .find(|entry| {
            entry.local.port() == local.port()
                && entry.local.ip().is_unspecified()
                && entry.local.is_ipv4() == local.is_ipv4()
        })
        .map(|entry| entry.pid)
}

impl Default for WindowsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowOwnerResolver for WindowsResolver {
    fn owner_of(&self, network: Network, local: SocketAddr) -> Option<ProcessIdentity> {
        let pid = self.pid_of(network, local)?;
        self.identities
            .get_or_insert(pid, || path::identity_of(pid))
    }

    fn invalidate(&self) {
        self.tcp.lock().taken = None;
        self.udp.lock().taken = None;
        self.identities.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_owner_of_our_own_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("сокет");
        let local = listener.local_addr().expect("адрес");

        let resolver = WindowsResolver::new();
        let owner = resolver
            .owner_of(Network::Tcp, local)
            .expect("владелец найден");

        assert_eq!(owner.pid, std::process::id());
        assert!(
            owner.name.ends_with(".exe"),
            "неожиданное имя: {}",
            owner.name
        );
    }

    #[test]
    fn unknown_socket_has_no_owner() {
        let resolver = WindowsResolver::new();
        let local: SocketAddr = "127.0.0.1:1".parse().expect("адрес");
        let _ = resolver.owner_of(Network::Tcp, local);
    }

    #[test]
    fn wildcard_socket_is_matched_by_port() {
        let entries = vec![Entry {
            local: "0.0.0.0:8080".parse().expect("адрес"),
            pid: 4242,
        }];
        let incoming: SocketAddr = "192.168.1.5:8080".parse().expect("адрес");
        assert_eq!(find(&entries, incoming), Some(4242));
    }

    #[test]
    fn wildcard_match_respects_the_family() {
        let entries = vec![Entry {
            local: "[::]:8080".parse().expect("адрес"),
            pid: 1,
        }];
        let incoming: SocketAddr = "192.168.1.5:8080".parse().expect("адрес");
        assert_eq!(find(&entries, incoming), None);
    }

    #[test]
    fn exact_match_wins_over_wildcard() {
        let entries = vec![
            Entry {
                local: "0.0.0.0:8080".parse().expect("адрес"),
                pid: 1,
            },
            Entry {
                local: "192.168.1.5:8080".parse().expect("адрес"),
                pid: 2,
            },
        ];
        let incoming: SocketAddr = "192.168.1.5:8080".parse().expect("адрес");
        assert_eq!(find(&entries, incoming), Some(2));
    }

    #[test]
    fn invalidate_forces_a_fresh_read() {
        let resolver = WindowsResolver::new();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("сокет");
        let local = listener.local_addr().expect("адрес");

        resolver
            .owner_of(Network::Tcp, local)
            .expect("владелец найден");
        resolver.invalidate();
        assert!(resolver.tcp.lock().taken.is_none());
        resolver
            .owner_of(Network::Tcp, local)
            .expect("владелец найден снова");
    }
}
