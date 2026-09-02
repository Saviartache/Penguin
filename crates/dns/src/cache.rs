//! Кэш ответов с учётом TTL.
//!
//! Приложения спрашивают одно и то же постоянно: браузер открывает страницу и
//! разрешает десяток имён, часть из которых он спрашивал минуту назад. Без
//! кэша каждый такой запрос уходил бы наружу и добавлял к загрузке страницы
//! оборот до сервера.
//!
//! TTL берётся из самого ответа — так велит DNS. Нижняя граница нужна, чтобы
//! сервер с нулевым TTL не превращал кэш в украшение; верхней нет: запись
//! всё равно вытеснится по объёму.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use hickory_proto::rr::RecordType;
use parking_lot::Mutex;

/// Сколько ответов помнить.
pub const MAX_ENTRIES: usize = 4096;

/// Ключ: имя и тип записи.
///
/// Тип обязателен: `A` и `AAAA` для одного имени — разные ответы, и путать
/// их значило бы отдавать приложению адрес не того семейства.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    name: String,
    record_type: RecordType,
}

#[derive(Debug, Clone)]
struct Entry {
    response: Vec<u8>,
    expires: Instant,
}

/// Кэш ответов DNS.
#[derive(Debug, Default)]
pub struct DnsCache {
    entries: Mutex<HashMap<Key, Entry>>,
    min_ttl: u32,
}

impl DnsCache {
    /// Заводит кэш с нижней границей времени жизни.
    pub fn new(min_ttl: u32) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            min_ttl,
        }
    }

    /// Ответ из кэша.
    pub fn get(&self, name: &str, record_type: RecordType) -> Option<Vec<u8>> {
        let key = Key {
            name: name.to_owned(),
            record_type,
        };
        let mut entries = self.entries.lock();

        let entry = entries.get(&key)?;
        if entry.expires <= Instant::now() {
            // Просроченное убирается сразу: иначе оно копится до вытеснения
            // по объёму и занимает место живых записей.
            entries.remove(&key);
            return None;
        }
        Some(entry.response.clone())
    }

    /// Запоминает ответ.
    ///
    /// `ttl` — из самого ответа; ниже настроенной границы не опускается.
    pub fn insert(&self, name: &str, record_type: RecordType, response: Vec<u8>, ttl: u32) {
        let ttl = ttl.max(self.min_ttl);
        if ttl == 0 {
            return;
        }

        let mut entries = self.entries.lock();
        if entries.len() >= MAX_ENTRIES {
            Self::evict(&mut entries);
        }

        entries.insert(
            Key {
                name: name.to_owned(),
                record_type,
            },
            Entry {
                response,
                expires: Instant::now() + Duration::from_secs(u64::from(ttl)),
            },
        );
    }

    /// Сколько ответов помнится.
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// Кэш пуст.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Забывает всё.
    ///
    /// Вызывается при переподключении: ответы прежнего сервера могли
    /// отличаться от ответов нового.
    pub fn clear(&self) {
        self.entries.lock().clear();
    }

    fn evict(entries: &mut HashMap<Key, Entry>) {
        let now = Instant::now();
        entries.retain(|_, entry| entry.expires > now);

        // Просроченного не нашлось — записи свежие, их просто много.
        while entries.len() >= MAX_ENTRIES {
            let Some(soonest) = entries
                .iter()
                .min_by_key(|(_, e)| e.expires)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            entries.remove(&soonest);
        }
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
        // `A` и `AAAA` для одного имени — разные ответы; путать их значит
        // отдать приложению адрес не того семейства.
        let cache = cache();
        cache.insert("example.com", RecordType::A, vec![1], 60);
        assert!(cache.get("example.com", RecordType::AAAA).is_none());
    }

    #[test]
    fn zero_ttl_is_not_cached() {
        // Ответ с нулевым TTL сервер просит не запоминать.
        let cache = cache();
        cache.insert("example.com", RecordType::A, vec![1], 0);
        assert!(cache.get("example.com", RecordType::A).is_none());
    }

    #[test]
    fn minimum_ttl_lifts_short_answers() {
        // Сервер с нулевым TTL не должен превращать кэш в украшение.
        let cache = DnsCache::new(60);
        cache.insert("example.com", RecordType::A, vec![1], 0);
        assert!(cache.get("example.com", RecordType::A).is_some());
    }

    #[test]
    fn expired_entries_disappear() {
        let cache = cache();
        cache.insert("example.com", RecordType::A, vec![1], 1);

        // Подделываем истечение, не дожидаясь секунды.
        cache.entries.lock().values_mut().for_each(|entry| {
            entry.expires = Instant::now() - Duration::from_secs(1);
        });

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
    fn clear_forgets_everything() {
        let cache = cache();
        cache.insert("example.com", RecordType::A, vec![1], 60);
        cache.clear();
        assert!(cache.is_empty());
    }
}
