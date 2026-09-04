//! macOS: libproc.
//!
//! Интерфейса «кому принадлежит порт» в системе нет, и ответ собирается
//! перебором: список процессов, у каждого — список сокетов, у каждого сокета
//! — его локальный адрес ([`libproc`]).
//!
//! Перебор дорог, поэтому его результат — таблица «адрес → процесс» — живёт
//! коротким снимком, и все обращения за этот срок отвечаются из него.
//!
//! Срок жизни снимка — компромисс. Слишком долгий врёт: порт освободился и
//! достался другому процессу. Слишком короткий возвращает нас к перебору на
//! каждое соединение. Полсекунды — заметно меньше времени, за которое система
//! переиспользует порт, и заметно больше пачки соединений, которую браузер
//! открывает при загрузке страницы.

pub mod libproc;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use penguin_core::network::Network;

use crate::cache::IdentityCache;
use crate::enumerate::ProcessEnumerator;
use crate::identity::ProcessIdentity;
use crate::resolver::FlowOwnerResolver;

/// Сколько живёт снимок таблицы.
const SNAPSHOT_TTL: Duration = Duration::from_millis(500);

/// Поиск владельца соединения в macOS.
#[derive(Debug)]
pub struct MacosResolver {
    sockets: Mutex<Snapshot>,
    identities: IdentityCache,
}

#[derive(Debug, Default)]
struct Snapshot {
    /// Адрес сокета и процесс, который его держит.
    owners: HashMap<SocketAddr, u32>,
    taken: Option<Instant>,
}

impl Snapshot {
    fn is_fresh(&self, now: Instant) -> bool {
        self.taken
            .is_some_and(|taken| now.duration_since(taken) < SNAPSHOT_TTL)
    }
}

impl MacosResolver {
    /// Создаёт резолвер.
    pub fn new() -> Self {
        Self {
            sockets: Mutex::new(Snapshot::default()),
            identities: IdentityCache::new(),
        }
    }

    /// Номер процесса, которому принадлежит локальный адрес.
    ///
    /// Вид трафика не участвует: система называет адрес сокета, не разделяя
    /// TCP и UDP, а одинаковый адрес у двух разных сокетов означал бы, что
    /// один из них уже закрыт.
    fn pid_of(&self, local: SocketAddr) -> Option<u32> {
        let mut snapshot = self.sockets.lock();
        let now = Instant::now();
        if !snapshot.is_fresh(now) {
            snapshot.owners = owners();
            snapshot.taken = Some(now);
        }

        if let Some(pid) = find(&snapshot.owners, local) {
            return Some(pid);
        }

        // Соединение могло появиться уже после снимка. Один повторный заход
        // со свежим перебором — этого хватает: соединение, которого нет и в
        // нём, скорее всего уже закрылось.
        snapshot.owners = owners();
        snapshot.taken = Some(Instant::now());
        find(&snapshot.owners, local)
    }
}

/// Перебирает процессы и собирает таблицу «адрес → процесс».
fn owners() -> HashMap<SocketAddr, u32> {
    let mut table = HashMap::new();
    for pid in libproc::all_pids() {
        for address in libproc::local_addresses(pid) {
            table.insert(address, pid);
        }
    }
    table
}

/// Ищет процесс по локальному адресу.
///
/// Сначала точное совпадение адреса и порта, потом — только по порту.
/// Второй заход нужен для сокетов, привязанных к `0.0.0.0` или `[::]`: система
/// показывает их именно так, а соединение приходит с конкретного адреса.
fn find(owners: &HashMap<SocketAddr, u32>, local: SocketAddr) -> Option<u32> {
    if let Some(pid) = owners.get(&local) {
        return Some(*pid);
    }

    owners
        .iter()
        .find(|(address, _)| address.port() == local.port() && address.ip().is_unspecified())
        .map(|(_, pid)| *pid)
}

/// Личность процесса по его номеру.
fn identity_of(pid: u32) -> Option<ProcessIdentity> {
    Some(ProcessIdentity::new(pid, libproc::path_of(pid)?))
}

impl Default for MacosResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowOwnerResolver for MacosResolver {
    fn owner_of(&self, _network: Network, local: SocketAddr) -> Option<ProcessIdentity> {
        let pid = self.pid_of(local)?;
        self.identities.get_or_insert(pid, || identity_of(pid))
    }

    fn invalidate(&self) {
        self.sockets.lock().taken = None;
        self.identities.clear();
    }
}

/// Список запущенных приложений.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosEnumerator;

impl ProcessEnumerator for MacosEnumerator {
    fn list(&self) -> Vec<ProcessIdentity> {
        libproc::all_pids()
            .into_iter()
            // Процессы без своего файла — служебные; показывать их в списке
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
        // Сквозная проверка всей цепочки: сокет -> перебор -> pid -> путь.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("сокет");
        let local = listener.local_addr().expect("адрес");

        let resolver = MacosResolver::new();
        let owner = resolver
            .owner_of(Network::Tcp, local)
            .expect("владелец найден");

        assert_eq!(owner.pid, std::process::id());
        assert!(!owner.name.is_empty(), "имя не определилось");
    }

    #[test]
    fn unknown_socket_has_no_owner() {
        let resolver = MacosResolver::new();
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
        let mut owners = HashMap::new();
        owners.insert("0.0.0.0:8080".parse().expect("адрес"), 4242);

        let incoming: SocketAddr = "192.168.1.5:8080".parse().expect("адрес");
        assert_eq!(find(&owners, incoming), Some(4242));
    }

    #[test]
    fn exact_match_wins_over_wildcard() {
        let mut owners = HashMap::new();
        owners.insert("0.0.0.0:8080".parse().expect("адрес"), 1);
        owners.insert("192.168.1.5:8080".parse().expect("адрес"), 2);

        let incoming: SocketAddr = "192.168.1.5:8080".parse().expect("адрес");
        assert_eq!(find(&owners, incoming), Some(2));
    }

    #[test]
    fn we_are_in_the_list_of_running_apps() {
        let apps = MacosEnumerator.list_apps();
        assert!(!apps.is_empty(), "список приложений пуст");
    }
}
