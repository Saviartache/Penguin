//! Linux: procfs.
//!
//! Ответ собирается в два шага: таблица соединений даёт inode сокета
//! ([`procfs`]), обход `/proc/*/fd` — процесс, который его держит ([`fd`]).
//!
//! Первый шаг дорог: таблица читается целиком, дешёвых способов спросить про
//! один порт ядро не даёт. Поэтому снимок живёт короткое время, и все
//! обращения за этот срок отвечаются из него.
//!
//! Срок жизни снимка — компромисс. Слишком долгий врёт: порт освободился и
//! достался другому процессу. Слишком короткий возвращает нас к чтению всей
//! таблицы на каждое соединение. Полсекунды — заметно меньше времени, за
//! которое система переиспользует порт, и заметно больше пачки соединений,
//! которую браузер открывает при загрузке страницы.

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

    /// Номер процесса, которому принадлежит локальный адрес.
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

        // Соединение могло появиться уже после снимка. Один повторный заход
        // со свежей таблицей — этого хватает: соединение, которого нет и в
        // ней, скорее всего уже закрылось.
        snapshot.entries = procfs::snapshot(network);
        snapshot.taken = Some(Instant::now());
        find(&snapshot.entries, local).and_then(fd::owner_of)
    }
}

/// Ищет запись по локальному адресу.
///
/// Сначала точное совпадение адреса и порта, потом — только по порту.
/// Второй заход нужен для сокетов, привязанных к `0.0.0.0` или `[::]`: система
/// показывает их именно так, а соединение приходит с конкретного адреса.
fn find(entries: &[Entry], local: SocketAddr) -> Option<u64> {
    if let Some(entry) = entries.iter().find(|entry| entry.local == local) {
        return Some(entry.inode);
    }

    entries
        .iter()
        .find(|entry| entry.local.port() == local.port() && entry.local.ip().is_unspecified())
        .map(|entry| entry.inode)
}

/// Личность процесса по его номеру.
///
/// Путь берётся из `/proc/<pid>/exe`: это ссылка на сам файл, и подменить её
/// процесс не может — в отличие от `cmdline`, который он пишет себе сам.
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
            // Процессы без своего файла — потоки ядра; показывать их в списке
            // приложений незачем, и правило на них всё равно не напишешь.
            .filter_map(identity_of)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_owner_of_our_own_socket() {
        // Сквозная проверка всей цепочки: сокет -> таблица -> inode -> pid ->
        // путь.
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
        // Порт, которого почти наверняка нет ни у кого.
        let local: SocketAddr = "127.0.0.1:1".parse().expect("адрес");
        // Ответ может быть и `Some`, если кто-то и правда слушает первый порт;
        // важно, что вызов не паникует и не виснет.
        let _ = resolver.owner_of(Network::Tcp, local);
    }

    #[test]
    fn wildcard_socket_is_matched_by_port() {
        // Сокет на `0.0.0.0` система показывает именно так, а соединение
        // приходит с конкретного адреса — без второго захода владелец
        // не нашёлся бы.
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
