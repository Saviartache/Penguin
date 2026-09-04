//! Пул сессий: одно направление, много соединений TLS.
//!
//! # Зачем
//!
//! Рукопожатие TLS стоит два оборота до сервера. Если платить им за каждую
//! вкладку браузера, весь смысл мультиплексирования пропадает. Поэтому
//! сессия, у которой закрылся последний поток, не закрывается, а ложится в
//! пул и ждёт следующего.
//!
//! # Правило выбора
//!
//! Берётся **самая новая** свободная сессия, закрывается — **самая старая**.
//! Так у эталона, и причина не в скорости: старая сессия успела намолчаться,
//! и её закрытие выглядит обычным концом разговора, а не обрывом.
//!
//! # Почему не мультиплексировать всё в одну сессию
//!
//! Свободная сессия уходит из пула вместе с потоком и возвращается, когда
//! тот закроется. Значит на одной сессии обычно живёт один поток. Это не
//! экономия ради экономии: все потоки одной сессии едут в одном соединении
//! TCP, и потерянный пакет останавливает их все разом. Мультиплексирование
//! здесь избавляет от рукопожатий, а не от очереди.

use std::cmp::Reverse;
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, Instant};

use penguin_proto::error::ProtocolError;

use crate::config::AnyTlsConfig;
use crate::connector::Connector;
use crate::padding::Padding;
use crate::session::{Session, lock};
use crate::stream::AnyTlsStream;

/// Пул сессий одного направления.
pub struct SessionPool {
    connector: Connector,
    /// Схема дополнения: у сессий она общая, потому что общий сервер.
    padding: Arc<Padding>,
    /// Как представляться серверу.
    client: String,
    /// После какого простоя закрывать сессию.
    idle_timeout: Duration,
    /// Сколько свободных сессий держать про запас.
    min_idle: usize,
    /// Номер следующей сессии.
    seq: AtomicU64,
    /// Что у пула есть.
    state: StdMutex<State>,
    /// Ссылка на себя: её получают сессии, чтобы вернуться в пул.
    me: Weak<SessionPool>,
}

/// Сессии пула.
#[derive(Debug, Default)]
struct State {
    /// Все живые сессии.
    all: HashMap<u64, Arc<Session>>,
    /// Свободные, новейшие первыми.
    idle: BTreeSet<Reverse<u64>>,
}

impl std::fmt::Debug for SessionPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = lock(&self.state);
        f.debug_struct("SessionPool")
            .field("connector", &self.connector)
            .field("sessions", &state.all.len())
            .field("idle", &state.idle.len())
            .finish()
    }
}

impl SessionPool {
    /// Заводит пул. Соединений при этом не открывается.
    pub fn new(config: &AnyTlsConfig, connector: Connector) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            connector,
            padding: Arc::new(Padding::new()),
            client: config.client_name().to_owned(),
            idle_timeout: config.idle_timeout(),
            min_idle: config.min_idle_sessions,
            seq: AtomicU64::new(0),
            state: StdMutex::new(State::default()),
            me: me.clone(),
        })
    }

    /// Открывает поток: в свободной сессии или в новой.
    ///
    /// Свободная сессия могла умереть, пока лежала: сервер закрывает их по
    /// своему сроку, и узнаём мы об этом только при попытке писать. Поэтому
    /// неудача на сессии из пула — повод попробовать ещё раз на новой, а не
    /// показывать человеку ошибку.
    pub async fn open(&self) -> Result<AnyTlsStream, ProtocolError> {
        if let Some(session) = self.acquire() {
            match session.open_stream().await {
                Ok(stream) => return Ok(stream),
                Err(err) => {
                    tracing::debug!(seq = session.seq(), %err, "сессия из пула не годится");
                    self.forget(session.seq());
                }
            }
        }

        let session = self.create().await?;
        Ok(session.open_stream().await?)
    }

    /// Возвращает освободившуюся сессию в пул.
    pub fn release(&self, session: Arc<Session>) {
        if session.is_dead() {
            self.forget(session.seq());
            return;
        }
        let mut state = lock(&self.state);
        if state.all.contains_key(&session.seq()) {
            state.idle.insert(Reverse(session.seq()));
        }
    }

    /// Убирает сессию из пула. Последняя ссылка на неё гасит её задачи.
    pub fn forget(&self, seq: u64) {
        let mut state = lock(&self.state);
        state.idle.remove(&Reverse(seq));
        state.all.remove(&seq);
    }

    /// Закрывает свободные сессии, простоявшие дольше срока.
    ///
    /// Запас, заданный настройкой `min_idle_sessions`, не трогает: готовая сессия избавляет
    /// следующее соединение от рукопожатия TLS, и держать её про запас — это
    /// настройка, а не утечка.
    pub fn cleanup(&self) {
        let expired = Instant::now().checked_sub(self.idle_timeout);
        let mut state = lock(&self.state);

        let mut kept = 0;
        let mut closing = Vec::new();
        for Reverse(seq) in state.idle.iter().copied().collect::<Vec<_>>() {
            let Some(session) = state.all.get(&seq) else {
                closing.push(seq);
                continue;
            };
            if session.is_dead() {
                closing.push(seq);
                continue;
            }
            let stale = expired.is_some_and(|when| session.idle_since() < when);
            if !stale || kept < self.min_idle {
                kept += 1;
                continue;
            }
            closing.push(seq);
        }

        for seq in closing {
            state.idle.remove(&Reverse(seq));
            state.all.remove(&seq);
        }
    }

    /// Закрывает все сессии направления.
    pub fn close_all(&self) {
        let mut state = lock(&self.state);
        state.idle.clear();
        state.all.clear();
    }

    /// Сколько сессий живо. Нужно журналу и тестам.
    pub fn len(&self) -> usize {
        lock(&self.state).all.len()
    }

    /// Есть ли хоть одна сессия.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Берёт самую новую свободную сессию.
    fn acquire(&self) -> Option<Arc<Session>> {
        let mut state = lock(&self.state);
        while let Some(Reverse(seq)) = state.idle.iter().next().copied() {
            state.idle.remove(&Reverse(seq));
            match state.all.get(&seq) {
                Some(session) if !session.is_dead() => return Some(Arc::clone(session)),
                // Мёртвая сессия в пуле — обычное дело: сервер закрывает их
                // по своему сроку, и узнаём мы об этом задачей чтения.
                _ => {
                    state.all.remove(&seq);
                }
            }
        }
        None
    }

    /// Поднимает новую сессию.
    async fn create(&self) -> Result<Arc<Session>, ProtocolError> {
        let io = self.connector.connect(&self.padding).await?;
        let seq = self.seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);

        let session = Session::start(
            seq,
            io,
            Arc::clone(&self.padding),
            &self.client,
            self.me.clone(),
        )?;
        lock(&self.state).all.insert(seq, Arc::clone(&session));
        tracing::debug!(seq, "поднята сессия AnyTLS");
        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use tokio::io::DuplexStream;
    use tokio::net::{TcpStream, UdpSocket};

    use super::*;

    /// Пул без сети: проверяется учёт сессий, а не соединение.
    fn pool(idle_timeout: Duration, min_idle: usize) -> Arc<SessionPool> {
        Arc::new_cyclic(|me| SessionPool {
            connector: connector(),
            padding: Arc::new(Padding::new()),
            client: "penguin/тест".to_owned(),
            idle_timeout,
            min_idle,
            seq: AtomicU64::new(0),
            state: StdMutex::new(State::default()),
            me: me.clone(),
        })
    }

    /// Соединитель, которым не пользуются: сессии заводятся вручную.
    fn connector() -> Connector {
        let config = AnyTlsConfig {
            server: "example.com:443".to_owned(),
            password: "secret".to_owned(),
            ..AnyTlsConfig::default()
        };
        Connector::new(&config, Arc::new(NoDialer)).expect("собирается")
    }

    /// Звонящий, который никуда не звонит.
    #[derive(Debug)]
    struct NoDialer;

    #[async_trait::async_trait]
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

    /// Заводит сессию поверх заглушки соединения.
    ///
    /// Вторую половину заглушки тест обязан держать: без неё задача чтения
    /// тут же увидит конец и объявит сессию мёртвой.
    fn session(pool: &Arc<SessionPool>) -> (Arc<Session>, DuplexStream) {
        let (client, server) = tokio::io::duplex(4096);
        let seq = pool.seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let session = Session::start(
            seq,
            Box::new(client),
            Arc::clone(&pool.padding),
            &pool.client,
            Arc::downgrade(pool),
        )
        .expect("сессия поднимается");
        lock(&pool.state).all.insert(seq, Arc::clone(&session));
        (session, server)
    }

    #[tokio::test]
    async fn the_newest_free_session_is_the_one_handed_out() {
        // Самая новая — та, что дольше всех проживёт: у сервера свой срок, и
        // старая закроется первой.
        let pool = pool(Duration::from_secs(30), 0);
        let (first, _a) = session(&pool);
        let (second, _b) = session(&pool);

        pool.release(Arc::clone(&first));
        pool.release(Arc::clone(&second));

        assert_eq!(pool.acquire().map(|s| s.seq()), Some(second.seq()));
        assert_eq!(pool.acquire().map(|s| s.seq()), Some(first.seq()));
        assert!(pool.acquire().is_none(), "сессию выдали дважды");
    }

    #[tokio::test]
    async fn a_dead_session_is_never_handed_out() {
        let pool = pool(Duration::from_secs(30), 0);
        let (session, _keep) = session(&pool);
        pool.release(Arc::clone(&session));
        session.mark_dead("сервер ушёл");

        assert!(pool.acquire().is_none());
        assert!(pool.is_empty(), "мёртвая сессия осталась в пуле");
    }

    #[tokio::test]
    async fn a_session_still_working_is_not_free() {
        let pool = pool(Duration::from_secs(30), 0);
        let (session, _keep) = session(&pool);
        let _stream = session.open_stream().await.expect("поток открывается");

        // В пул её никто не отдавал: она занята.
        assert!(pool.acquire().is_none());
        assert!(!session.is_idle());
    }

    #[tokio::test]
    async fn a_session_that_stood_idle_too_long_is_closed() {
        let fresh = pool(Duration::from_secs(30), 0);
        let (young, _alive) = session(&fresh);
        fresh.release(young);

        fresh.cleanup();
        assert_eq!(fresh.len(), 1, "срок ещё не вышел");

        let stale = pool(Duration::ZERO, 0);
        let (expired, _keep) = session(&stale);
        stale.release(expired);
        stale.cleanup();
        assert!(stale.is_empty(), "просроченная сессия осталась");
    }

    #[tokio::test]
    async fn the_reserve_of_free_sessions_survives_the_cleanup() {
        // Срок нулевой: просрочены обе, но одну велено держать про запас.
        let pool = pool(Duration::ZERO, 1);
        let (first, _a) = session(&pool);
        let (second, _b) = session(&pool);
        pool.release(first);
        pool.release(second);

        pool.cleanup();
        assert_eq!(pool.len(), 1, "запас не сохранился или сохранился весь");
    }

    #[tokio::test]
    async fn a_closed_pool_keeps_nothing() {
        let pool = pool(Duration::from_secs(30), 0);
        let (session, _keep) = session(&pool);
        pool.release(session);

        pool.close_all();
        assert!(pool.is_empty());
        assert!(pool.acquire().is_none());
    }
}
