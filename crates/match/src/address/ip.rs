//! CIDR-префиксы в дереве: поиск за длину адреса, а не за число правил.
//!
//! Перебор списка подсетей стоит столько же, сколько в нём записей, а списки
//! бывают длинными: один только набор адресов России — это тысячи префиксов.
//! Двоичное дерево по битам адреса ищет за длину адреса — 32 шага для IPv4 и
//! 128 для IPv6, — сколько бы префиксов в него ни положили.

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

use crate::matcher::Matcher;
use crate::target::MatchTarget;

/// Набор подсетей.
#[derive(Debug, Default)]
pub struct IpSet {
    v4: Node,
    v6: Node,
    /// Исходные записи — только для описания правила в интерфейсе.
    labels: Vec<String>,
}

/// Узел двоичного дерева префиксов.
#[derive(Debug, Default)]
struct Node {
    /// Здесь заканчивается какой-то префикс.
    terminal: bool,
    children: [Option<Box<Node>>; 2],
}

impl Node {
    /// Добавляет префикс.
    fn insert(&mut self, bits: &[u8], prefix_len: u8) {
        let mut node = self;
        for index in 0..prefix_len as usize {
            // Уже есть более короткий префикс, покрывающий этот: длинный
            // ничего не добавляет, и хранить его незачем.
            if node.terminal {
                return;
            }
            let bit = usize::from(bit_at(bits, index));
            node = node.children[bit].get_or_insert_with(Box::default);
        }
        node.terminal = true;
        // Более длинные префиксы под этим узлом стали лишними.
        node.children = [None, None];
    }

    /// Есть ли префикс, покрывающий адрес.
    fn contains(&self, bits: &[u8], total_len: u8) -> bool {
        let mut node = self;
        for index in 0..total_len as usize {
            if node.terminal {
                return true;
            }
            let bit = usize::from(bit_at(bits, index));
            match &node.children[bit] {
                Some(child) => node = child,
                None => return false,
            }
        }
        node.terminal
    }
}

/// Бит по номеру, старшими вперёд.
fn bit_at(bits: &[u8], index: usize) -> u8 {
    let byte = bits[index / 8];
    (byte >> (7 - index % 8)) & 1
}

impl IpSet {
    /// Пустой набор.
    pub fn new() -> Self {
        Self::default()
    }

    /// Собирает набор из записей CIDR.
    ///
    /// Голый адрес без длины префикса означает один адрес: `1.2.3.4` — то же,
    /// что `1.2.3.4/32`. Пользователь пишет именно так, и заставлять его
    /// дописывать `/32` незачем.
    pub fn parse<I, S>(entries: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut set = Self::new();
        for entry in entries {
            let entry = entry.as_ref().trim();
            let net = IpNet::from_str(entry)
                .or_else(|_| IpAddr::from_str(entry).map(IpNet::from))
                .map_err(|_| format!("не разбирается как подсеть: `{entry}`"))?;
            set.insert(net);
            set.labels.push(entry.to_owned());
        }
        Ok(set)
    }

    /// Добавляет подсеть.
    pub fn insert(&mut self, net: IpNet) {
        match net {
            IpNet::V4(v4) => self.v4.insert(&v4.network().octets(), v4.prefix_len()),
            IpNet::V6(v6) => self.v6.insert(&v6.network().octets(), v6.prefix_len()),
        }
    }

    /// Покрыт ли адрес набором.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.v4.contains(&v4.octets(), 32),
            IpAddr::V6(v6) => self.v6.contains(&v6.octets(), 128),
        }
    }

    /// Набор пуст.
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }
}

impl Matcher for IpSet {
    fn matches(&self, target: &MatchTarget<'_>) -> bool {
        // Адреса может не быть вовсе: приложение через прокси отдало имя и
        // разрешать его будет сервер. Условию по подсети такое соединение не
        // подходит — симметрично тому, как условие по домену не подходит
        // соединению без имени.
        target.destination_ip.is_some_and(|ip| self.contains(ip))
    }

    fn describe(&self) -> String {
        format!("адрес в [{}]", self.labels.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(entries: &[&str]) -> IpSet {
        IpSet::parse(entries).expect("разбирается")
    }

    fn ip(raw: &str) -> IpAddr {
        raw.parse().expect("адрес")
    }

    #[test]
    fn matches_inside_the_prefix() {
        let set = set(&["10.0.0.0/8"]);
        assert!(set.contains(ip("10.1.2.3")));
        assert!(set.contains(ip("10.255.255.255")));
        assert!(!set.contains(ip("11.0.0.1")));
    }

    #[test]
    fn bare_address_means_a_single_host() {
        let set = set(&["1.2.3.4"]);
        assert!(set.contains(ip("1.2.3.4")));
        assert!(!set.contains(ip("1.2.3.5")));
    }

    #[test]
    fn handles_ipv6() {
        let set = set(&["2001:db8::/32"]);
        assert!(set.contains(ip("2001:db8::1")));
        assert!(!set.contains(ip("2001:db9::1")));
    }

    #[test]
    fn families_do_not_mix() {
        // `::/0` покрывает весь IPv6 и не должен зацепить ни одного IPv4.
        let set = set(&["::/0"]);
        assert!(set.contains(ip("2001:db8::1")));
        assert!(!set.contains(ip("1.2.3.4")));
    }

    #[test]
    fn shorter_prefix_absorbs_longer() {
        // Добавление `/8` делает лежащий под ним `/24` лишним, и наоборот:
        // порядок добавления не должен менять результат.
        let mut first = set(&["10.0.0.0/8", "10.1.2.0/24"]);
        let second = set(&["10.1.2.0/24", "10.0.0.0/8"]);
        for probe in ["10.1.2.3", "10.9.9.9"] {
            assert!(first.contains(ip(probe)));
            assert!(second.contains(ip(probe)));
        }
        first.insert("192.168.0.0/16".parse().expect("подсеть"));
        assert!(first.contains(ip("192.168.1.1")));
    }

    #[test]
    fn default_route_matches_everything() {
        let set = set(&["0.0.0.0/0"]);
        assert!(set.contains(ip("8.8.8.8")));
        assert!(set.contains(ip("127.0.0.1")));
    }

    #[test]
    fn lan_ranges_work_together() {
        // Ровно то правило, которое стоит первым почти у всех.
        let set = set(&[
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
        ]);
        for probe in ["10.0.0.1", "172.16.5.5", "192.168.1.1", "127.0.0.1"] {
            assert!(
                set.contains(ip(probe)),
                "{probe} должен считаться локальным"
            );
        }
        for probe in ["8.8.8.8", "172.32.0.1", "193.168.1.1"] {
            assert!(!set.contains(ip(probe)), "{probe} локальным не является");
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(IpSet::parse(["не адрес"]).is_err());
        assert!(IpSet::parse(["10.0.0.0/99"]).is_err());
    }

    #[test]
    fn empty_set_matches_nothing() {
        let set = IpSet::new();
        assert!(set.is_empty());
        assert!(!set.contains(ip("1.2.3.4")));
    }
}
