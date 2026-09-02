//! Кэш pid -> личность с инвалидацией по завершению процесса: pid переиспользуются.
//!
//! Путь по номеру процесса стоит трёх системных вызовов, а браузер открывает
//! десятки соединений в секунду — все от одного и того же процесса. Без кэша
//! эти вызовы повторялись бы на каждое соединение.
//!
//! Опасность у кэша ровно одна, и она настоящая: система переиспользует
//! номера. Процесс завершился, номер достался другому, а в кэше лежит старый
//! путь — и правило применилось не к тому приложению. Поэтому записи живут
//! недолго, а при переподключении сбрасываются целиком.

use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::identity::ProcessIdentity;

/// Сколько живёт запись.
///
/// Тридцать секунд — заметно меньше, чем нужно системе, чтобы пройти круг по
/// номерам процессов, и заметно больше, чем длится пачка соединений одного
/// приложения.
const TTL: Duration = Duration::from_secs(30);

/// Сколько записей помнить.
///
/// Потолок нужен на случай, когда процессы создаются и умирают потоком:
/// сборщик мусора у кэша срабатывает по времени, и без потолка память между
/// его срабатываниями растёт неограниченно.
const MAX_ENTRIES: usize = 4096;

/// Кэш личностей процессов.
#[derive(Debug, Default)]
pub struct IdentityCache {
    entries: DashMap<u32, CacheEntry>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    identity: Option<ProcessIdentity>,
    stored: Instant,
}

impl IdentityCache {
    /// Пустой кэш.
    pub fn new() -> Self {
        Self::default()
    }

    /// Отдаёт личность из кэша или вычисляет её.
    ///
    /// Отрицательный ответ тоже запоминается: процесс, до которого нет
    /// доступа, не станет доступнее от повторного вопроса, а спрашивать про
    /// него будут на каждое его соединение.
    pub fn get_or_insert<F>(&self, pid: u32, compute: F) -> Option<ProcessIdentity>
    where
        F: FnOnce() -> Option<ProcessIdentity>,
    {
        let now = Instant::now();

        if let Some(entry) = self.entries.get(&pid)
            && now.duration_since(entry.stored) < TTL
        {
            return entry.identity.clone();
        }

        let identity = compute();

        if self.entries.len() >= MAX_ENTRIES {
            self.evict_stale(now);
        }
        self.entries.insert(
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
        self.entries.clear();
    }

    /// Сколько записей в кэше.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Кэш пуст.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Выбрасывает просроченное; если не помогло — половину самого старого.
    fn evict_stale(&self, now: Instant) {
        self.entries
            .retain(|_, entry| now.duration_since(entry.stored) < TTL);

        if self.entries.len() < MAX_ENTRIES {
            return;
        }

        // Просроченного не нашлось — значит, записи свежие и их просто много.
        // Отдельные ключи собираются заранее: удалять во время обхода
        // `DashMap` нельзя.
        let mut by_age: Vec<(u32, Instant)> =
            self.entries.iter().map(|e| (*e.key(), e.stored)).collect();
        by_age.sort_unstable_by_key(|(_, stored)| *stored);

        for (pid, _) in by_age.into_iter().take(MAX_ENTRIES / 2) {
            self.entries.remove(&pid);
        }
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
        // Процесс, до которого нет доступа, не станет доступнее от повторного
        // вопроса, а спрашивать про него будут на каждое его соединение.
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
        // Повторный запрос отдаёт своё, а не соседское.
        assert_eq!(
            cache.get_or_insert(1, || None).expect("есть").path,
            first.path
        );
    }
}
