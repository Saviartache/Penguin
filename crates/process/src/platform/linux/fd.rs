//! Обход `/proc/*/fd`: по номеру inode сокета — процесс-владелец.
//!
//! Вторая половина ответа на вопрос «чей это порт»: первую даёт таблица
//! соединений ([`super::procfs`]), в которой лежит только inode.
//!
//! Обход недёшев — каталогов столько, сколько процессов в системе, — и потому
//! идёт с прерыванием на первом совпадении, а результат кладётся в кэш
//! ([`crate::cache::IdentityCache`]).
//!
//! Читать чужие каталоги вправе только суперпользователь. Демон под ним и
//! работает; запущенный иначе, клиент просто не найдёт владельца, и такое
//! соединение уйдёт по умолчанию режима, а не будет заблокировано.

use std::path::Path;

/// Начало ссылки, которой система обозначает сокет.
const SOCKET: &str = "socket:[";

/// Ищет процесс, которому принадлежит сокет с таким inode.
pub(super) fn owner_of(inode: u64) -> Option<u32> {
    let processes = std::fs::read_dir("/proc").ok()?;

    for entry in processes.flatten() {
        let Some(pid) = pid_of(&entry.file_name().to_string_lossy()) else {
            continue;
        };
        if owns(pid, inode) {
            return Some(pid);
        }
    }
    None
}

/// Держит ли процесс сокет с таким inode.
fn owns(pid: u32, inode: u64) -> bool {
    let Ok(descriptors) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        // Процесс закрылся, пока мы шли по каталогу, или он чужой и читать
        // его нам не дали. И то и другое — обычное дело.
        return false;
    };

    descriptors.flatten().any(|descriptor| {
        std::fs::read_link(descriptor.path())
            .ok()
            .and_then(|link| socket_inode(&link))
            .is_some_and(|found| found == inode)
    })
}

/// Номер процесса из имени каталога в `/proc`.
///
/// В `/proc` лежат не только процессы: `self`, `net`, `sys` и десяток других
/// имён. Отсеиваются они разбором, а не списком: список пришлось бы
/// поддерживать вслед за ядром.
fn pid_of(name: &str) -> Option<u32> {
    name.parse().ok()
}

/// Номер inode из ссылки вида `socket:[24680]`.
fn socket_inode(link: &Path) -> Option<u64> {
    let text = link.to_str()?;
    let number = text.strip_prefix(SOCKET)?.strip_suffix(']')?;
    number.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_inode_from_a_socket_link() {
        assert_eq!(socket_inode(Path::new("socket:[24680]")), Some(24680));
    }

    #[test]
    fn other_links_are_not_sockets() {
        // В `/proc/*/fd` лежат ссылки на файлы, каналы и устройства; принять
        // любую из них за сокет значит найти не того владельца.
        assert!(socket_inode(Path::new("/dev/null")).is_none());
        assert!(socket_inode(Path::new("pipe:[24680]")).is_none());
        assert!(socket_inode(Path::new("socket:[24680")).is_none());
        assert!(socket_inode(Path::new("socket:[не число]")).is_none());
    }

    #[test]
    fn only_numbers_are_processes() {
        // В `/proc` лежат не только процессы.
        assert_eq!(pid_of("1234"), Some(1234));
        assert!(pid_of("self").is_none());
        assert!(pid_of("net").is_none());
    }

    #[test]
    fn our_own_socket_leads_back_to_us() {
        // Сквозная проверка обхода: сокет открыт этим самым процессом, и
        // найтись должен именно он.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("сокет");
        let inode = our_socket_inode(&listener).expect("inode нашёлся");

        assert_eq!(owner_of(inode), Some(std::process::id()));
    }

    /// Номер inode сокета, открытого нами самими.
    fn our_socket_inode(listener: &std::net::TcpListener) -> Option<u64> {
        use std::os::fd::AsRawFd;

        let path = format!("/proc/self/fd/{}", listener.as_raw_fd());
        socket_inode(&std::fs::read_link(path).ok()?)
    }
}
