//! Сессия: мультиплексор поверх одного соединения TLS.
//!
//! Один TLS несёт много потоков: читает все кадры одна задача и раскладывает
//! по очередям, пишут через один замок.
//!
//! Полузакрытия нет: `cmdFIN` закрывает поток целиком, поэтому `poll_shutdown`
//! его не шлёт. Очередь потока ограниченная: поток, из которого не читают,
//! останавливает всю сессию (так же и у эталона). Сессию держит пул, задачи
//! держат [`Weak`] и гасятся в `Drop`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use penguin_proto::stream::ProxyStream;
use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::error::{AnyTlsError, AnyTlsResult};
use crate::frame;
use crate::kv::Map;
use crate::padding::Padding;
use crate::pool::SessionPool;
use crate::reader;
use crate::stream::AnyTlsStream;
use crate::writer::Writer;

/// Версия протокола, которую объявляет клиент.
pub const VERSION: &str = "2";

/// Сколько кусков держать для потока, пока их не забрали.
const QUEUE: usize = 16;

/// Срок подтверждения открытия потока (версия 2): иначе сессия застряла.
const SYNACK_DEADLINE: Duration = Duration::from_secs(3);

/// Что приходит потоку из сессии.
#[derive(Debug)]
pub enum Msg {
    /// Данные.
    Data(Bytes),
    /// Собеседник закрыл поток.
    Eof,
    /// Сервер сообщил об ошибке вместо подтверждения.
    Failed(String),
}

/// Сессия AnyTLS.
pub struct Session {
    /// Номер сессии в направлении. Больше — новее.
    seq: u64,
    /// Пишущая сторона под замком: пишут в неё все потоки сразу.
    writer: Mutex<Writer<WriteHalf<Box<dyn ProxyStream>>>>,
    /// Схема дополнения направления.
    padding: Arc<Padding>,
    /// Пул, которому сессия принадлежит.
    pool: Weak<SessionPool>,
    /// Очереди потоков.
    streams: StdMutex<HashMap<u32, mpsc::Sender<Msg>>>,
    /// Номер следующего потока.
    next_sid: AtomicU32,
    /// Версия протокола на той стороне. Ноль — ещё не сказал.
    peer_version: AtomicU8,
    /// Сколько потоков живо.
    live: AtomicUsize,
    /// Почему сессия умерла. Пусто — жива.
    death: StdMutex<Option<String>>,
    /// С какого времени сессия простаивает.
    idle_since: StdMutex<Instant>,
    /// Сюда `Drop` потока кладёт номер закрывшегося.
    fin: mpsc::UnboundedSender<u32>,
    /// Сторож подтверждения открытия потока.
    synack: StdMutex<Option<JoinHandle<()>>>,
    /// Задачи сессии.
    tasks: StdMutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("seq", &self.seq)
            .field("live", &self.live.load(Ordering::Relaxed))
            .field("dead", &self.is_dead())
            .finish()
    }
}

impl Session {
    /// Поднимает сессию поверх опознанного соединения; настройки уедут с первым потоком.
    pub fn start(
        seq: u64,
        io: Box<dyn ProxyStream>,
        padding: Arc<Padding>,
        client: &str,
        pool: Weak<SessionPool>,
    ) -> AnyTlsResult<Arc<Self>> {
        let (read, write) = tokio::io::split(io);
        let (fin, closed) = mpsc::unbounded_channel();

        let mut writer = Writer::new(write);
        writer.stash(&settings(&padding, client)?);

        let session = Arc::new(Self {
            seq,
            writer: Mutex::new(writer),
            padding,
            pool,
            streams: StdMutex::new(HashMap::new()),
            next_sid: AtomicU32::new(0),
            peer_version: AtomicU8::new(0),
            live: AtomicUsize::new(0),
            death: StdMutex::new(None),
            idle_since: StdMutex::new(Instant::now()),
            fin,
            synack: StdMutex::new(None),
            tasks: StdMutex::new(Vec::new()),
        });

        let tasks = vec![
            tokio::spawn(reader::run(Arc::downgrade(&session), read)),
            tokio::spawn(close_loop(Arc::downgrade(&session), closed)),
        ];
        *lock(&session.tasks) = tasks;
        Ok(session)
    }

    /// Номер сессии.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Умерла ли сессия.
    pub fn is_dead(&self) -> bool {
        lock(&self.death).is_some()
    }

    /// Свободна ли сессия под новый поток.
    pub fn is_idle(&self) -> bool {
        self.live.load(Ordering::Acquire) == 0
    }

    /// С какого времени сессия простаивает.
    pub fn idle_since(&self) -> Instant {
        *lock(&self.idle_since)
    }

    /// Версия протокола на той стороне.
    pub fn peer_version(&self) -> u8 {
        self.peer_version.load(Ordering::Relaxed)
    }

    /// Запоминает версию, объявленную сервером.
    pub fn set_peer_version(&self, version: u8) {
        self.peer_version.store(version, Ordering::Relaxed);
    }

    /// Схема дополнения направления.
    pub fn padding(&self) -> &Padding {
        &self.padding
    }

    /// Пул, которому сессия принадлежит.
    pub fn pool(&self) -> Option<Arc<SessionPool>> {
        self.pool.upgrade()
    }

    /// Открывает поток; очередь заводится до `cmdSYN`, чтобы не потерять ответ.
    pub async fn open_stream(self: &Arc<Self>) -> AnyTlsResult<AnyTlsStream> {
        if let Some(reason) = self.death() {
            return Err(AnyTlsError::disconnected(reason));
        }

        let sid = self
            .next_sid
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        if sid == 0 {
            return Err(AnyTlsError::disconnected(
                "в сессии кончились номера потоков",
            ));
        }

        let (sender, receiver) = mpsc::channel(QUEUE);
        lock(&self.streams).insert(sid, sender);
        self.live.fetch_add(1, Ordering::AcqRel);

        if sid >= 2 && self.peer_version() >= 2 {
            self.watch_synack();
        }

        if let Err(err) = self.write_frame(frame::CMD_SYN, sid, &[]).await {
            self.forget_stream(sid);
            return Err(err);
        }

        self.writer.lock().await.release();

        Ok(AnyTlsStream::new(Arc::clone(self), sid, receiver))
    }

    /// Отправляет кадр.
    pub async fn write_frame(&self, cmd: u8, sid: u32, data: &[u8]) -> AnyTlsResult<()> {
        let len = u16::try_from(data.len()).map_err(|_| AnyTlsError::Oversized(data.len()))?;
        let mut writer = self.writer.lock().await;
        let scheme = self.padding.get();
        let written = writer
            .write_frame(&scheme, frame::Header { cmd, sid, len }, data)
            .await;
        drop(writer);

        written.map_err(|err| {
            self.mark_dead(format!("запись не прошла: {err}"));
            AnyTlsError::Io(err)
        })
    }

    /// Кладёт кусок в очередь потока, ожидая места.
    pub async fn deliver(&self, sid: u32, msg: Msg) {
        let sender = lock(&self.streams).get(&sid).cloned();
        if let Some(sender) = sender
            && sender.send(msg).await.is_err()
        {
            self.forget_stream(sid);
        }
    }

    /// Убирает поток из таблицы. Очередь при этом закрывается.
    pub fn forget_stream(&self, sid: u32) {
        if lock(&self.streams).remove(&sid).is_some()
            && self.live.fetch_sub(1, Ordering::AcqRel) == 1
        {
            *lock(&self.idle_since) = Instant::now();
        }
    }

    /// Сообщает, что поток закрылся у нас: сюда зовёт `Drop` потока.
    pub fn stream_closed(&self, sid: u32) {
        let _ = self.fin.send(sid);
    }

    /// Подтверждение открытия пришло: сторож больше не нужен.
    pub fn note_synack(&self) {
        if let Some(guard) = lock(&self.synack).take() {
            guard.abort();
        }
    }

    /// Объявляет сессию мёртвой. Очереди потоков закрываются.
    pub fn mark_dead(&self, reason: impl Into<String>) {
        let mut death = lock(&self.death);
        if death.is_none() {
            *death = Some(reason.into());
        }
        drop(death);

        lock(&self.streams).clear();
        self.live.store(0, Ordering::Release);
        *lock(&self.idle_since) = Instant::now();
    }

    /// Почему сессия умерла.
    pub fn death(&self) -> Option<String> {
        lock(&self.death).clone()
    }

    /// Закрывает свою половину соединения.
    pub async fn shutdown(&self) {
        let _ = self.writer.lock().await.get_mut().shutdown().await;
    }

    /// Заводит сторожа подтверждения.
    fn watch_synack(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let guard = tokio::spawn(async move {
            tokio::time::sleep(SYNACK_DEADLINE).await;
            let Some(session) = weak.upgrade() else {
                return;
            };
            tracing::debug!(
                seq = session.seq,
                "сервер не подтвердил открытие потока: сессия застряла"
            );
            session.mark_dead("сервер не подтвердил открытие потока");
            session.shutdown().await;
        });
        if let Some(previous) = lock(&self.synack).replace(guard) {
            previous.abort();
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        for task in lock(&self.tasks).drain(..) {
            task.abort();
        }
        if let Some(guard) = lock(&self.synack).take() {
            guard.abort();
        }
    }
}

/// Кадр настроек, который уходит первым.
fn settings(padding: &Padding, client: &str) -> AnyTlsResult<Vec<u8>> {
    let mut map = Map::new();
    map.set("v", VERSION);
    map.set("client", client);
    map.set("padding-md5", padding.get().md5());
    frame::encode(frame::CMD_SETTINGS, 0, &map.to_bytes())
}

/// Закрывает потоки, о которых сказал их `Drop` (тот не может ждать).
async fn close_loop(session: Weak<Session>, mut closed: mpsc::UnboundedReceiver<u32>) {
    while let Some(sid) = closed.recv().await {
        let Some(session) = session.upgrade() else {
            return;
        };
        session.forget_stream(sid);
        if session.is_dead() {
            continue;
        }
        let _ = session.write_frame(frame::CMD_FIN, sid, &[]).await;

        if session.is_idle()
            && let Some(pool) = session.pool()
        {
            pool.release(session);
        }
    }
}

/// Берёт замок, игнорируя отравление (`AGENTS.md` §4.3).
pub(crate) fn lock<T>(what: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    match what.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
