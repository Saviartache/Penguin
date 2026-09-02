//! Кэш решений. Горячий путь: правила не пересчитываются на каждый пакет.
//!
//! Разбор набора правил — это обход списка с проверкой условий; для одного
//! соединения это ничто, но браузер открывает их десятками в секунду, а
//! маршрутизатор вызывается дважды на каждое (до и после опознания имени).
//!
//! Ключ — то, от чего решение зависит: вид трафика, адрес назначения, имя и
//! путь процесса. Исходный порт в ключ **не** входит: он у каждого соединения
//! свой, и кэш с ним никогда бы не попадал.

use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::context::FlowContext;
use crate::decision::Verdict;

/// Сколько живёт запись.
///
/// Не про экономию памяти, а про правильность: подставные адреса fake-IP
/// переиспользуются, и решение, принятое для прежнего домена, не должно
/// пережить его.
const TTL: Duration = Duration::from_secs(60);

/// Сколько решений помнить.
const MAX_ENTRIES: usize = 8192;

/// Ключ решения.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    network: penguin_core::network::Network,
    destination_ip: Option<std::net::IpAddr>,
    port: u16,
    domain: Option<String>,
    process: Option<std::sync::Arc<str>>,
}

/// Кэш решений маршрутизатора.
#[derive(Debug, Default)]
pub struct DecisionCache {
    entries: DashMap<Key, (Verdict, Instant)>,
}

impl DecisionCache {
    /// Пустой кэш.
    pub fn new() -> Self {
        Self::default()
    }

    /// Решение из кэша.
    pub fn get(&self, flow: &FlowContext) -> Option<Verdict> {
        let key = key_of(flow);
        let entry = self.entries.get(&key)?;
        if entry.1.elapsed() >= TTL {
            return None;
        }
        Some(entry.0.clone())
    }

    /// Запоминает решение.
    pub fn insert(&self, flow: &FlowContext, verdict: &Verdict) {
        if self.entries.len() >= MAX_ENTRIES {
            self.evict();
        }
        self.entries
            .insert(key_of(flow), (verdict.clone(), Instant::now()));
    }

    /// Забывает всё.
    ///
    /// Вызывается при смене правил и при смене профиля: старые решения после
    /// этого не просто устарели, а стали неверными.
    pub fn clear(&self) {
        self.entries.clear();
    }

    /// Сколько решений запомнено.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Кэш пуст.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn evict(&self) {
        self.entries.retain(|_, (_, stored)| stored.elapsed() < TTL);

        if self.entries.len() < MAX_ENTRIES {
            return;
        }

        // Просроченного не нашлось — записи свежие, их просто много. Ключи
        // собираются заранее: удалять во время обхода `DashMap` нельзя.
        let mut by_age: Vec<(Key, Instant)> = self
            .entries
            .iter()
            .map(|e| (e.key().clone(), e.1))
            .collect();
        by_age.sort_unstable_by_key(|(_, stored)| *stored);

        for (key, _) in by_age.into_iter().take(MAX_ENTRIES / 2) {
            self.entries.remove(&key);
        }
    }
}

fn key_of(flow: &FlowContext) -> Key {
    Key {
        network: flow.network,
        destination_ip: flow.destination_ip(),
        port: flow.destination.port,
        domain: flow.domain().map(str::to_owned),
        process: flow.process.as_ref().map(|p| p.path.clone()),
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
        // Иначе кэш не попадал бы никогда: у каждого соединения свой порт.
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
        // Один и тот же адрес CDN обслуживает разные имена, и решения по ним
        // разные.
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
