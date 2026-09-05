//! Пул неявных соединений: одно направление, несколько TCP-соединений.
//!
//! # Своя политика, а не протокол
//!
//! Сервер принимает любое число сессий на одном соединении — сколько их
//! завести, решает только клиент. Здесь это `sessions_per_connection`
//! (`config`): пул отдаёт новой сессии любое существующее соединение, у
//! которого сессий меньше предела, и открывает новое, только когда все
//! заняты под завязку. Это отличается от AnyTLS
//! (`protocols/anytls/src/pool.rs`), где сессия из пула переиспользуется,
//! только когда она полностью свободна: там смысл сессии — избежать
//! рукопожатия TLS, здесь — избежать двух оборотов TCP до сервера, и второе
//! стоит настоящего совместного использования одного соединения.
//!
//! # Ключ выводится заново на каждое новое соединение
//!
//! Ключ Mieru зависит от текущего времени (`keying`), и держать его
//! посчитанным один раз на весь пул означало бы, что соединение, поднятое
//! через полчаса после включения профиля, попробует устаревший ключ.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use penguin_proto::error::ProtocolError;

use crate::config::MieruConfig;
use crate::connector::Connector;
use crate::keying;
use crate::stream::MieruStream;
use crate::underlay::Underlay;

/// Пул неявных соединений одного направления.
pub struct Pool {
    connector: Connector,
    username: Arc<str>,
    password: String,
    max_sessions: usize,
    idle_timeout: Duration,
    seq: AtomicU64,
    state: StdMutex<Vec<Arc<Underlay>>>,
}

impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("username", &self.username)
            .field("max_sessions", &self.max_sessions)
            .field("connections", &lock(&self.state).len())
            .finish()
    }
}

impl Pool {
    /// Заводит пул. Соединений при этом не открывается.
    pub fn new(config: &MieruConfig, connector: Connector) -> Arc<Self> {
        Arc::new(Self {
            connector,
            username: Arc::from(config.username.as_str()),
            password: config.password.clone(),
            max_sessions: config.sessions_per_connection,
            idle_timeout: config.idle_timeout(),
            seq: AtomicU64::new(0),
            state: StdMutex::new(Vec::new()),
        })
    }

    /// Открывает сессию: на существующем соединении со свободным местом или
    /// на новом.
    pub async fn open(&self) -> Result<MieruStream, ProtocolError> {
        if let Some(underlay) = self.acquire() {
            match underlay.open_session().await {
                Ok(stream) => return Ok(stream),
                Err(err) => {
                    tracing::debug!(seq = underlay.seq(), %err, "соединение из пула не годится");
                    self.forget(underlay.seq());
                }
            }
        }

        let underlay = self.create().await?;
        Ok(underlay.open_session().await?)
    }

    /// Закрывает все соединения направления.
    pub async fn close_all(&self) {
        let underlays: Vec<Arc<Underlay>> = lock(&self.state).drain(..).collect();
        for underlay in underlays {
            underlay.shutdown().await;
        }
    }

    /// Закрывает соединения, простоявшие без единой сессии дольше срока.
    pub fn cleanup(&self) {
        let expired = Instant::now().checked_sub(self.idle_timeout);
        lock(&self.state).retain(|underlay| {
            if underlay.is_dead() {
                return false;
            }
            if underlay.live_count() > 0 {
                return true;
            }
            !expired.is_some_and(|when| underlay.idle_since() < when)
        });
    }

    /// Сколько соединений сейчас живо. Нужно журналу и тестам.
    pub fn len(&self) -> usize {
        lock(&self.state).len()
    }

    /// Есть ли хоть одно соединение.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Ищет соединение со свободным местом под новую сессию.
    fn acquire(&self) -> Option<Arc<Underlay>> {
        lock(&self.state)
            .iter()
            .find(|underlay| underlay.has_room(self.max_sessions))
            .cloned()
    }

    /// Убирает соединение из пула.
    fn forget(&self, seq: u64) {
        lock(&self.state).retain(|underlay| underlay.seq() != seq);
    }

    /// Поднимает новое соединение.
    async fn create(&self) -> Result<Arc<Underlay>, ProtocolError> {
        let io = self.connector.connect().await?;
        let key = keying::derive(&self.username, &self.password, unix_seconds());
        let seq = self.seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);

        let underlay = Underlay::start(seq, io, &key, Arc::clone(&self.username));
        lock(&self.state).push(Arc::clone(&underlay));
        tracing::debug!(seq, "поднято соединение Mieru");
        Ok(underlay)
    }
}

/// Текущее время в секундах с начала эпохи. Расхождение часов назад даёт
/// `0`, а не панику, — на пути соединения паниковать нельзя (`AGENTS.md`
/// §4.3); последствие — ключ выведется из неверного времени и не подойдёт
/// серверу, что неотличимо от любой другой не сошедшейся метки подлинности.
fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Берёт замок, не роняя соединение из-за чужой паники.
fn lock<T>(what: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    match what.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use async_trait::async_trait;
    use tokio::net::{TcpStream, UdpSocket};

    use super::*;

    /// Звонящий, который никуда не звонит.
    #[derive(Debug)]
    struct NoDialer;

    #[async_trait]
    impl penguin_proto::dialer::Dialer for NoDialer {
        async fn dial_tcp(&self, _addr: SocketAddr) -> Result<TcpStream, ProtocolError> {
            Err(ProtocolError::Unsupported("сеть в тесте"))
        }

        async fn bind_udp(&self, _local: SocketAddr) -> Result<UdpSocket, ProtocolError> {
            Err(ProtocolError::Unsupported("сеть в тесте"))
        }

        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, ProtocolError> {
            Err(ProtocolError::Unsupported("сеть в тесте"))
        }
    }

    fn config() -> MieruConfig {
        MieruConfig {
            server: "example.com:2999".to_owned(),
            username: "alice".to_owned(),
            password: "secret".to_owned(),
            ..MieruConfig::default()
        }
    }

    fn pool() -> Arc<Pool> {
        let connector = Connector::new(&config(), Arc::new(NoDialer)).expect("собирается");
        Pool::new(&config(), connector)
    }

    #[tokio::test]
    async fn a_fresh_pool_holds_no_connections() {
        assert!(pool().is_empty());
    }

    #[test]
    fn cleanup_of_an_empty_pool_does_nothing() {
        pool().cleanup();
    }
}
