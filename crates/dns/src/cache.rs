//! Кэш ответов с учётом TTL.
//!
//! TTL берётся из ответа; нижняя граница не даёт серверу с нулевым TTL свести
//! кэш на нет. Верхней нет: запись вытеснится по объёму.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::message::RecordType;

/// Сколько ответов помнить.
pub const MAX_ENTRIES: usize = 4096;

#[derive(Debug, Clone)]
struct Entry {
    response: Vec<u8>,
    expires: Instant,
}

/// Имена по типам записи: поиск по `&str` обходится без аллокации ключа.
#[derive(Debug, Default)]
struct Store {
    by_type: HashMap<RecordType, HashMap<String, Entry>>,
    len: usize,
}

impl Store {
    fn remove(&mut self, name: &str, record_type: RecordType) {
        if let Some(names) = self.by_type.get_mut(&record_type)
            && names.remove(name).is_some()
        {
            self.len -= 1;
        }
    }

    /// Выбрасывает просроченное, а если все свежие — ближайшие к истечению.
    fn evict(&mut self) {
        let now = Instant::now();
        for names in self.by_type.values_mut() {
            names.retain(|_, entry| entry.expires > now);
        }
        self.recount();

        while self.len >= MAX_ENTRIES {
            let soonest = self
                .by_type
                .iter()
                .flat_map(|(ty, names)| names.iter().map(move |(name, e)| (e.expires, *ty, name)))
                .min_by_key(|(expires, ..)| *expires)
                .map(|(_, ty, name)| (ty, name.clone()));
            let Some((ty, name)) = soonest else { break };
            self.remove(&name, ty);
        }
    }

    fn recount(&mut self) {
        self.len = self.by_type.values().map(HashMap::len).sum();
    }
}

/// Кэш ответов DNS; ключ — имя и тип записи.
#[derive(Debug, Default)]
pub struct DnsCache {
    store: Mutex<Store>,
    min_ttl: u32,
}

impl DnsCache {
    /// Заводит кэш с нижней границей времени жизни.
    pub fn new(min_ttl: u32) -> Self {
        Self {
            store: Mutex::new(Store::default()),
            min_ttl,
        }
    }

    /// Ответ из кэша; просроченный убирается сразу.
    pub fn get(&self, name: &str, record_type: RecordType) -> Option<Vec<u8>> {
        let mut store = self.store.lock();
        let entry = store.by_type.get(&record_type)?.get(name)?;
        if entry.expires > Instant::now() {
            return Some(entry.response.clone());
        }
        store.remove(name, record_type);
        None
    }

    /// Запоминает ответ; `ttl` из ответа не опускается ниже границы кэша.
    pub fn insert(&self, name: &str, record_type: RecordType, response: Vec<u8>, ttl: u32) {
        let ttl = ttl.max(self.min_ttl);
        if ttl == 0 {
            return;
        }
        let entry = Entry {
            response,
            expires: Instant::now() + Duration::from_secs(u64::from(ttl)),
        };

        let mut store = self.store.lock();
        if store.len >= MAX_ENTRIES {
            store.evict();
        }
        let names = store.by_type.entry(record_type).or_default();
        if names.insert(name.to_owned(), entry).is_none() {
            store.len += 1;
        }
    }

    /// Сколько ответов помнится.
    pub fn len(&self) -> usize {
        self.store.lock().len
    }

    /// Кэш пуст.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Забывает всё: при переподключении ответы прежнего сервера могут не подойти.
    pub fn clear(&self) {
        *self.store.lock() = Store::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache() -> DnsCache {
        DnsCache::new(0)
    }

    #[test]
    fn remembers_and_returns() {
        let cache = cache();
        cache.insert("example.com", RecordType::A, vec![1, 2, 3], 60);
        assert_eq!(cache.get("example.com", RecordType::A), Some(vec![1, 2, 3]));
    }

    #[test]
    fn record_type_is_part_of_the_key() {
        let cache = cache();
        cache.insert("example.com", RecordType::A, vec![1], 60);
        assert!(cache.get("example.com", RecordType::AAAA).is_none());
    }

    #[test]
    fn zero_ttl_is_not_cached() {
        let cache = cache();
        cache.insert("example.com", RecordType::A, vec![1], 0);
        assert!(cache.get("example.com", RecordType::A).is_none());
    }

    #[test]
    fn minimum_ttl_lifts_short_answers() {
        let cache = DnsCache::new(60);
        cache.insert("example.com", RecordType::A, vec![1], 0);
        assert!(cache.get("example.com", RecordType::A).is_some());
    }

    #[test]
    fn expired_entries_disappear() {
        let cache = cache();
        cache.insert("example.com", RecordType::A, vec![1], 1);

        // Подделываем истечение, не дожидаясь секунды.
        for names in cache.store.lock().by_type.values_mut() {
            for entry in names.values_mut() {
                entry.expires = Instant::now() - Duration::from_secs(1);
            }
        }

        assert!(cache.get("example.com", RecordType::A).is_none());
        // Просроченное убирается сразу, а не копится до вытеснения.
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_is_bounded() {
        let cache = cache();
        for step in 0..(MAX_ENTRIES + 200) {
            cache.insert(&format!("host{step}.example"), RecordType::A, vec![1], 3600);
        }
        assert!(cache.len() <= MAX_ENTRIES, "кэш вырос до {}", cache.len());
    }

    #[test]
    fn overwrite_does_not_grow_the_count() {
        let cache = cache();
        cache.insert("example.com", RecordType::A, vec![1], 60);
        cache.insert("example.com", RecordType::A, vec![2], 60);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get("example.com", RecordType::A), Some(vec![2]));
    }

    #[test]
    fn clear_forgets_everything() {
        let cache = cache();
        cache.insert("example.com", RecordType::A, vec![1], 60);
        cache.clear();
        assert!(cache.is_empty());
    }
}
