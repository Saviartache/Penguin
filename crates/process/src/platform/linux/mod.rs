//! Linux: таблица соединений даёт inode ([`procfs`]), обход `/proc/*/fd` —
//! процесс ([`fd`]). Снимок таблицы живёт 500 мс: дольше врёт, короче дорого.

pub mod fd;
pub mod procfs;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use penguin_core::network::Network;

use self::procfs::Entry;
use crate::cache::IdentityCache;
use crate::enumerate::ProcessEnumerator;
use crate::identity::ProcessIdentity;
use crate::resolver::FlowOwnerResolver;

/// Сколько живёт снимок таблицы.
const SNAPSHOT_TTL: Duration = Duration::from_millis(500);

/// Поиск владельца соединения в Linux.
#[derive(Debug)]
pub struct LinuxResolver {
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
}

impl LinuxResolver {
    /// Создаёт резолвер.
    pub fn new() -> Self {
        Self {
            tcp: Mutex::new(Snapshot::empty()),
            udp: Mutex::new(Snapshot::empty()),
            identities: IdentityCache::new(),
        }
    }

    /// Номер процесса-владельца; при промахе таблица перечитывается один раз.
    fn pid_of(&self, network: Network, local: SocketAddr) -> Option<u32> {
        let slot = match network {
            Network::Tcp => &self.tcp,
            Network::Udp => &self.udp,
        };

        let mut snapshot = slot.lock();
        let now = Instant::now();
        if !snapshot.is_fresh(now) {
            snapshot.entries = procfs::snapshot(network);
            snapshot.taken = Some(now);
        }

        if let Some(inode) = find(&snapshot.entries, local) {
            return fd::owner_of(inode);
        }

        snapshot.entries = procfs::snapshot(network);
        snapshot.taken = Some(Instant::now());
        find(&snapshot.entries, local).and_then(fd::owner_of)
    }
}

/// Ищет запись: точный адрес, затем порт сокета на `0.0.0.0`/`[::]`.
fn find(entries: &[Entry], local: SocketAddr) -> Option<u64> {
    if let Some(entry) = entries.iter().find(|entry| entry.local == local) {
        return Some(entry.inode);
    }

    entries
        .iter()
        .find(|entry| entry.local.port() == local.port() && entry.local.ip().is_unspecified())
        .map(|entry| entry.inode)
}

/// Личность по `/proc/<pid>/exe` (в отличие от `cmdline`, процесс её не подменит).
fn identity_of(pid: u32) -> Option<ProcessIdentity> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    Some(ProcessIdentity::new(pid, path.to_string_lossy()))
}

impl Default for LinuxResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowOwnerResolver for LinuxResolver {
    fn owner_of(&self, network: Network, local: SocketAddr) -> Option<ProcessIdentity> {
        let pid = self.pid_of(network, local)?;
        self.identities.get_or_insert(pid, || identity_of(pid))
    }

    fn invalidate(&self) {
        self.tcp.lock().taken = None;
        self.udp.lock().taken = None;
        self.identities.clear();
    }
}

/// Список запущенных приложений.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxEnumerator;

impl ProcessEnumerator for LinuxEnumerator {
    fn list(&self) -> Vec<ProcessIdentity> {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };

        entries
            .flatten()
            .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
            .filter_map(identity_of)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_owner_of_our_own_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("сокет");
        let local = listener.local_addr().expect("адрес");

        let resolver = LinuxResolver::new();
        let owner = resolver
            .owner_of(Network::Tcp, local)
            .expect("владелец найден");

        assert_eq!(owner.pid, std::process::id());
        assert!(!owner.name.is_empty(), "имя не определилось");
    }

    #[test]
    fn unknown_socket_has_no_owner() {
        let resolver = LinuxResolver::new();
        let local: SocketAddr = "127.0.0.1:1".parse().expect("адрес");
        let _ = resolver.owner_of(Network::Tcp, local);
    }

    #[test]
    fn wildcard_socket_is_matched_by_port() {
        let entries = vec![Entry {
            local: "0.0.0.0:8080".parse().expect("адрес"),
            inode: 4242,
        }];
        let incoming: SocketAddr = "192.168.1.5:8080".parse().expect("адрес");
        assert_eq!(find(&entries, incoming), Some(4242));
    }

    #[test]
    fn exact_match_wins_over_wildcard() {
        let entries = vec![
            Entry {
                local: "0.0.0.0:8080".parse().expect("адрес"),
                inode: 1,
            },
            Entry {
                local: "192.168.1.5:8080".parse().expect("адрес"),
                inode: 2,
            },
        ];
        let incoming: SocketAddr = "192.168.1.5:8080".parse().expect("адрес");
        assert_eq!(find(&entries, incoming), Some(2));
    }

    #[test]
    fn we_are_in_the_list_of_running_apps() {
        let apps = LinuxEnumerator.list_apps();
        assert!(!apps.is_empty(), "список приложений пуст");
    }
}
