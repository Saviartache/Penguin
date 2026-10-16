//! Таблица UDP-сессий: вытеснение по таймауту и предел размера.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::session::{Session, SessionKey};

/// Сколько сессий держать одновременно.
pub const MAX_SESSIONS: usize = 8192;

/// Как часто чистить таблицу при вставке.
const SWEEP_EVERY: Duration = Duration::from_secs(1);

/// Таблица UDP-сессий.
#[derive(Debug, Default)]
pub struct SessionTable {
    sessions: HashMap<SessionKey, Session>,
    last_sweep: Option<Instant>,
}

impl SessionTable {
    /// Пустая таблица.
    pub fn new() -> Self {
        Self::default()
    }

    /// Отмечает прохождение датаграммы; `true` — сессия новая (или просроченная и заведена заново).
    pub fn touch(&mut self, key: SessionKey, now: Instant) -> bool {
        if let Some(session) = self.sessions.get_mut(&key)
            && !session.is_expired(now)
        {
            session.touch(now);
            return false;
        }

        let due = self
            .last_sweep
            .is_none_or(|last| now.duration_since(last) >= SWEEP_EVERY);
        if due || self.sessions.len() >= MAX_SESSIONS {
            self.last_sweep = Some(now);
            self.expire(now);
        }
        self.sessions.insert(key, Session::new(key, now));
        true
    }

    /// Есть ли такая сессия.
    pub fn contains(&self, key: &SessionKey) -> bool {
        self.sessions.contains_key(key)
    }

    /// Убирает сессию.
    pub fn remove(&mut self, key: &SessionKey) {
        self.sessions.remove(key);
    }

    /// Сколько сессий живо.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Таблица пуста.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Выбрасывает просроченные и лишние; возвращает их ключи.
    pub fn expire(&mut self, now: Instant) -> Vec<SessionKey> {
        let mut dropped: Vec<SessionKey> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.is_expired(now))
            .map(|(key, _)| *key)
            .collect();

        for key in &dropped {
            self.sessions.remove(key);
        }

        // `>=`: сразу после вызывающий добавит запись.
        while self.sessions.len() >= MAX_SESSIONS {
            let Some(oldest) = self
                .sessions
                .iter()
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.sessions.remove(&oldest);
            dropped.push(oldest);
        }

        dropped
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use super::super::session::SESSION_TIMEOUT;
    use super::*;

    fn key(source_port: u16, destination: &str) -> SessionKey {
        let source: SocketAddr = format!("10.0.0.2:{source_port}").parse().expect("адрес");
        SessionKey {
            source,
            destination: destination.parse().expect("адрес"),
        }
    }

    #[test]
    fn first_datagram_creates_a_session() {
        let mut table = SessionTable::new();
        let now = Instant::now();

        assert!(
            table.touch(key(50000, "8.8.8.8:53"), now),
            "первая датаграмма не создала сессию"
        );
        assert!(
            !table.touch(key(50000, "8.8.8.8:53"), now),
            "вторая создала сессию заново"
        );
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn different_destinations_are_different_sessions() {
        let mut table = SessionTable::new();
        let now = Instant::now();

        assert!(table.touch(key(50000, "8.8.8.8:53"), now));
        assert!(table.touch(key(50000, "1.1.1.1:53"), now));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn silence_expires_a_session() {
        let mut table = SessionTable::new();
        let now = Instant::now();
        table.touch(key(50000, "8.8.8.8:53"), now);

        let dropped = table.expire(now + SESSION_TIMEOUT + Duration::from_secs(1));
        assert_eq!(dropped.len(), 1);
        assert!(table.is_empty());
    }

    #[test]
    fn traffic_keeps_a_session_alive() {
        let mut table = SessionTable::new();
        let start = Instant::now();
        let session = key(50000, "8.8.8.8:53");

        table.touch(session, start);
        let later = start + SESSION_TIMEOUT - Duration::from_secs(1);
        table.touch(session, later);

        assert!(table.expire(later + Duration::from_secs(1)).is_empty());
        assert!(table.contains(&session));
    }

    #[test]
    fn table_is_bounded() {
        let mut table = SessionTable::new();
        let now = Instant::now();
        for step in 0..(MAX_SESSIONS as u32 + 64) {
            let destination = format!("8.8.8.{}:{}", step % 256, 1000 + step % 1000);
            table.touch(key((step % 60000) as u16, &destination), now);
        }
        assert!(
            table.len() <= MAX_SESSIONS,
            "таблица выросла до {}",
            table.len()
        );
    }

    #[test]
    fn removal_works() {
        let mut table = SessionTable::new();
        let session = key(50000, "8.8.8.8:53");
        table.touch(session, Instant::now());
        table.remove(&session);
        assert!(!table.contains(&session));
    }
}
