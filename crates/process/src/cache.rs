//! Кэш pid -> личность; записи короткоживущие, так как pid переиспользуются.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::identity::ProcessIdentity;

/// Время жизни записи.
const TTL: Duration = Duration::from_secs(30);

/// Потолок числа записей.
const MAX_ENTRIES: usize = 4096;

/// Кэш личностей процессов.
#[derive(Debug, Default)]
pub struct IdentityCache {
    entries: Mutex<HashMap<u32, CacheEntry>>,
}

#[derive(Debug)]
struct CacheEntry {
    identity: Option<ProcessIdentity>,
    stored: Instant,
}

impl IdentityCache {
    /// Пустой кэш.
    pub fn new() -> Self {
        Self::default()
    }

    /// Отдаёт личность из кэша или вычисляет её; отрицательный ответ тоже кэшируется.
    pub fn get_or_insert<F>(&self, pid: u32, compute: F) -> Option<ProcessIdentity>
    where
        F: FnOnce() -> Option<ProcessIdentity>,
    {
        let now = Instant::now();

        if let Some(entry) = self.entries.lock().get(&pid)
            && now.duration_since(entry.stored) < TTL
        {
            return entry.identity.clone();
        }

        let identity = compute();

        let mut entries = self.entries.lock();
        if entries.len() >= MAX_ENTRIES {
            evict(&mut entries, now);
        }
        entries.insert(
            pid,
            CacheEntry {
                identity: identity.clone(),
                stored: now,
            },
        );
        identity
    }

    /// Забывает всё.
    pub fn clear(&self) {
        self.entries.lock().clear();
    }

    /// Сколько записей в кэше.
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// Кэш пуст.
    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }
}

/// Выбрасывает просроченное; если не помогло, половину самого старого.
fn evict(entries: &mut HashMap<u32, CacheEntry>, now: Instant) {
    entries.retain(|_, entry| now.duration_since(entry.stored) < TTL);
    if entries.len() < MAX_ENTRIES {
        return;
    }

    let mut by_age: Vec<(u32, Instant)> = entries.iter().map(|(k, e)| (*k, e.stored)).collect();
    by_age.sort_unstable_by_key(|(_, stored)| *stored);
    for (pid, _) in by_age.into_iter().take(MAX_ENTRIES / 2) {
        entries.remove(&pid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(pid: u32) -> Option<ProcessIdentity> {
        Some(ProcessIdentity::new(pid, format!("/bin/app{pid}")))
    }

    #[test]
    fn computes_once_and_reuses() {
        let cache = IdentityCache::new();
        let mut calls = 0;

        for _ in 0..10 {
            cache.get_or_insert(42, || {
                calls += 1;
                identity(42)
            });
        }
        assert_eq!(calls, 1, "личность вычислена больше одного раза");
    }

    #[test]
    fn remembers_negative_answers() {
        let cache = IdentityCache::new();
        let mut calls = 0;

        for _ in 0..5 {
            let result = cache.get_or_insert(7, || {
                calls += 1;
                None
            });
            assert!(result.is_none());
        }
        assert_eq!(calls, 1);
    }

    #[test]
    fn clear_forgets_everything() {
        let cache = IdentityCache::new();
        cache.get_or_insert(1, || identity(1));
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn stays_within_the_cap() {
        let cache = IdentityCache::new();
        for pid in 0..(MAX_ENTRIES as u32 * 2) {
            cache.get_or_insert(pid, || identity(pid));
        }
        assert!(cache.len() <= MAX_ENTRIES, "кэш вырос до {}", cache.len());
    }

    #[test]
    fn returns_the_right_identity_per_pid() {
        let cache = IdentityCache::new();
        let first = cache.get_or_insert(1, || identity(1)).expect("есть");
        let second = cache.get_or_insert(2, || identity(2)).expect("есть");
        assert_ne!(first.path, second.path);
        assert_eq!(
            cache.get_or_insert(1, || None).expect("есть").path,
            first.path
        );
    }
}
