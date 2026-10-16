//! Кэш решений: ключ — вид трафика, адрес, порт назначения, имя и путь процесса.
//! Исходный порт в ключ не входит, иначе кэш никогда не попадал бы.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use penguin_core::network::Network;

use crate::context::FlowContext;
use crate::decision::Verdict;

/// Время жизни записи: адреса fake-IP переиспользуются, старое решение не должно пережить домен.
const TTL: Duration = Duration::from_secs(60);

/// Потолок числа решений.
const MAX_ENTRIES: usize = 8192;

/// Ключ записи; хранится ради проверки на коллизию хэша.
#[derive(Debug)]
struct Key {
    network: Network,
    destination_ip: Option<IpAddr>,
    port: u16,
    domain: Option<Box<str>>,
    process: Option<Box<str>>,
}

impl Key {
    fn of(flow: &FlowContext) -> Self {
        Self {
            network: flow.network,
            destination_ip: flow.destination_ip(),
            port: flow.destination.port,
            domain: flow.domain().map(Into::into),
            process: flow.process.as_ref().map(|p| (&*p.path).into()),
        }
    }

    fn is(&self, flow: &FlowContext) -> bool {
        self.network == flow.network
            && self.destination_ip == flow.destination_ip()
            && self.port == flow.destination.port
            && self.domain.as_deref() == flow.domain()
            && self.process.as_deref() == flow.process.as_ref().map(|p| &*p.path)
    }
}

#[derive(Debug)]
struct Entry {
    key: Key,
    verdict: Verdict,
    stored: Instant,
}

/// Кэш решений маршрутизатора.
#[derive(Debug, Default)]
pub struct DecisionCache {
    hasher: RandomState,
    entries: RwLock<HashMap<u64, Entry>>,
}

impl DecisionCache {
    /// Пустой кэш.
    pub fn new() -> Self {
        Self::default()
    }

    // Хэш по заимствованным полям: поиск без аллокаций.
    fn hash(&self, flow: &FlowContext) -> u64 {
        self.hasher.hash_one((
            flow.network,
            flow.destination_ip(),
            flow.destination.port,
            flow.domain(),
            flow.process.as_ref().map(|p| &*p.path),
        ))
    }

    /// Решение из кэша.
    pub fn get(&self, flow: &FlowContext) -> Option<Verdict> {
        let hash = self.hash(flow);
        let entries = self.entries.read();
        let entry = entries.get(&hash)?;
        (entry.stored.elapsed() < TTL && entry.key.is(flow)).then(|| entry.verdict.clone())
    }

    /// Запоминает решение.
    pub fn insert(&self, flow: &FlowContext, verdict: &Verdict) {
        let hash = self.hash(flow);
        let mut entries = self.entries.write();
        if entries.len() >= MAX_ENTRIES {
            evict(&mut entries);
        }
        entries.insert(
            hash,
            Entry {
                key: Key::of(flow),
                verdict: verdict.clone(),
                stored: Instant::now(),
            },
        );
    }

    /// Забывает всё; вызывается при смене правил и профиля.
    pub fn clear(&self) {
        self.entries.write().clear();
    }

    /// Сколько решений запомнено.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Кэш пуст.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

/// Выбрасывает просроченное; если не помогло, половину самого старого.
fn evict(entries: &mut HashMap<u64, Entry>) {
    entries.retain(|_, e| e.stored.elapsed() < TTL);
    if entries.len() < MAX_ENTRIES {
        return;
    }

    let mut by_age: Vec<(u64, Instant)> = entries.iter().map(|(k, e)| (*k, e.stored)).collect();
    by_age.sort_unstable_by_key(|(_, stored)| *stored);
    for (hash, _) in by_age.into_iter().take(MAX_ENTRIES / 2) {
        entries.remove(&hash);
    }
}

#[cfg(test)]
mod tests {
    use penguin_core::address::Address;
    use penguin_core::network::Network;
    use penguin_process::identity::ProcessIdentity;

    use super::*;
    use crate::decision::ResolvedDecision;

    fn flow(destination: &str) -> FlowContext {
        FlowContext::to_address(
            Network::Tcp,
            "127.0.0.1:50000".parse().expect("адрес"),
            destination.parse().expect("адрес"),
        )
    }

    fn verdict() -> Verdict {
        Verdict::by_mode(ResolvedDecision::Direct)
    }

    #[test]
    fn remembers_and_returns() {
        let cache = DecisionCache::new();
        assert!(cache.get(&flow("1.2.3.4:443")).is_none());
        cache.insert(&flow("1.2.3.4:443"), &verdict());
        assert_eq!(
            cache.get(&flow("1.2.3.4:443")).expect("есть").decision,
            ResolvedDecision::Direct
        );
    }

    #[test]
    fn source_port_is_not_part_of_the_key() {
        let cache = DecisionCache::new();
        let mut first = flow("1.2.3.4:443");
        first.source = "127.0.0.1:11111".parse().expect("адрес");
        cache.insert(&first, &verdict());

        let mut second = flow("1.2.3.4:443");
        second.source = "127.0.0.1:22222".parse().expect("адрес");
        assert!(cache.get(&second).is_some());
    }

    #[test]
    fn domain_is_part_of_the_key() {
        let cache = DecisionCache::new();
        let with_name = flow("1.2.3.4:443").with_domain(Address::domain("a.example"));
        cache.insert(&with_name, &verdict());

        let other_name = flow("1.2.3.4:443").with_domain(Address::domain("b.example"));
        assert!(cache.get(&other_name).is_none());
    }

    #[test]
    fn process_is_part_of_the_key() {
        let cache = DecisionCache::new();
        let chrome = flow("1.2.3.4:443").with_process(ProcessIdentity::new(1, "/apps/chrome"));
        cache.insert(&chrome, &verdict());

        let editor = flow("1.2.3.4:443").with_process(ProcessIdentity::new(2, "/apps/editor"));
        assert!(cache.get(&editor).is_none());
    }

    #[test]
    fn network_is_part_of_the_key() {
        let cache = DecisionCache::new();
        cache.insert(&flow("1.2.3.4:53"), &verdict());

        let mut udp = flow("1.2.3.4:53");
        udp.network = Network::Udp;
        assert!(cache.get(&udp).is_none());
    }

    #[test]
    fn clear_forgets_everything() {
        let cache = DecisionCache::new();
        cache.insert(&flow("1.2.3.4:443"), &verdict());
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn stays_within_the_cap() {
        let cache = DecisionCache::new();
        for port in 0..(MAX_ENTRIES as u32 * 2) {
            cache.insert(&flow(&format!("1.2.3.4:{}", port % 65535)), &verdict());
        }
        assert!(cache.len() <= MAX_ENTRIES, "кэш вырос до {}", cache.len());
    }
}
