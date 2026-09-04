//! Сессия: мультиплексор поверх одного соединения TLS.
//!
//! # Что здесь происходит
//!
//! Одно соединение TLS несёт сколько угодно потоков приложения. Каждый кадр
//! подписан номером потока; читает их всех одна задача и раскладывает по
//! очередям, пишут — все желающие через один замок.
//!
//! ```text
//!   поток 1 ─┐                        ┌─► очередь 1 ─► приложение
//!   поток 2 ─┼─► замок ─► запись TLS  ┼─► очередь 2 ─► приложение
//!   поток 3 ─┘                        └─► очередь 3 ─► приложение
//!                     чтение TLS ─► задача чтения
//! ```
//!
//! # Чего у сессии нет
//!
//! **Полузакрытия.** `cmdFIN` закрывает поток целиком, в обе стороны, — и
//! потому его не шлёт `poll_shutdown` потока: сервер удалил бы поток до того,
//! как ответил. Приложение, которое ждёт ответа после «я всё сказал», через
//! AnyTLS его не дождётся. Это свойство протокола, а не реализации.
//!
//! **Раздельных очередей.** Очередь потока ограничена, и задача чтения ждёт
//! на ней места. Значит поток, из которого не читают, останавливает **всю**
//! сессию. Так же устроен эталон — там очереди нет вовсе, — и лечится это не
//! здесь, а тем, что движок читает обе стороны сразу.
//!
//! # Кто кого держит
//!
//! Сессию держит пул, а не потоки: поток, закрывшись, должен успеть сказать
//! об этом серверу, и умереть раньше своего `cmdFIN` сессия не вправе. Задачи
//! сессии держат [`Weak`] — иначе она не умерла бы никогда — и гасятся в
//! `Drop`.

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
///
/// У эталона очереди нет вовсе: задача чтения ждёт, пока прочитают. Здесь
/// небольшой запас — он смягчает то же самое, но не отменяет.
const QUEUE: usize = 16;

/// Сколько ждать подтверждения открытия потока.
///
/// Ради этого срока и придумана версия 2 протокола: оборванное соединение, о
/// котором не пришло `RST`, иначе висит до системного срока — а это минуты.
/// Не пришло подтверждение — сессия считается застрявшей.
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
    /// Поднимает сессию поверх уже опознанного соединения.
    ///
    /// Настройки при этом не уходят: они кладутся в буфер и уедут первой
    /// записью вместе с открытием потока — так велит схема дополнения.
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

    /// Открывает поток и просит сервер открыть его у себя.
    ///
    /// Очередь заводится **до** отправки `cmdSYN`: ответ может прийти раньше,
    /// чем вернётся вызов, и потерять первый кусок нельзя.
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

        // Первый поток сторожить нечем: версию сервера мы узнаём из его
        // настроек, а они приходят в ответ на наши.
        if sid >= 2 && self.peer_version() >= 2 {
            self.watch_synack();
        }

        if let Err(err) = self.write_frame(frame::CMD_SYN, sid, &[]).await {
            self.forget_stream(sid);
            return Err(err);
        }

        // Буфер начала отпускает тот, кто открыл поток: следующей записью
        // уедут настройки, открытие и адрес назначения разом.
        self.writer.lock().await.release();

        Ok(AnyTlsStream::new(Arc::clone(self), sid, receiver))
    }

    /// Отправляет кадр.
    pub async fn write_frame(&self, cmd: u8, sid: u32, data: &[u8]) -> AnyTlsResult<()> {
        let bytes = frame::encode(cmd, sid, data)?;
        let mut writer = self.writer.lock().await;
        // Схема берётся под замком: сервер мог прислать новую, и две записи
        // подряд по разным схемам сбили бы счёт пакетов.
        let scheme = self.padding.get();
        let written = writer.write(&scheme, &bytes).await;
        drop(writer);

        written.map_err(|err| {
            self.mark_dead(format!("запись не прошла: {err}"));
            AnyTlsError::Io(err)
        })
    }

    /// Кладёт кусок в очередь потока.
    ///
    /// Ждёт места: терять данные потока нельзя, а места нет — значит из него
    /// не читают.
    pub async fn deliver(&self, sid: u32, msg: Msg) {
        let sender = lock(&self.streams).get(&sid).cloned();
        if let Some(sender) = sender
            && sender.send(msg).await.is_err()
        {
            // Поток исчез, пока мы ждали места: деть данные больше некуда.
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
        // Канал без границ: `Drop` не имеет права ждать. Ошибка означает, что
        // задача закрытия уже ушла, — значит и закрывать нечего.
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
    ///
    /// Зовётся задачей чтения на выходе: сервер уже ушёл, и держать сокет
    /// открытым до уборки пула незачем.
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

/// Закрывает потоки, о которых сказал их `Drop`.
///
/// Своя задача, а не `tokio::spawn` внутри `Drop`: `Drop` не имеет права ни
/// ждать, ни требовать, чтобы вокруг был запущен исполнитель.
async fn close_loop(session: Weak<Session>, mut closed: mpsc::UnboundedReceiver<u32>) {
    while let Some(sid) = closed.recv().await {
        let Some(session) = session.upgrade() else {
            return;
        };
        session.forget_stream(sid);
        if session.is_dead() {
            continue;
        }
        // Ошибку глотаем нарочно: сессия о своей смерти узнает из неё сама, а
        // закрывать поток в мёртвой сессии нечем.
        let _ = session.write_frame(frame::CMD_FIN, sid, &[]).await;

        if session.is_idle()
            && let Some(pool) = session.pool()
        {
            pool.release(session);
        }
    }
}

/// Берёт замок, не роняя соединение из-за чужой паники.
///
/// Отравленный замок означает, что кто-то запаниковал, держа его. Данные под
/// ним при этом целы — таблица потоков и причина смерти. Ронять из-за этого
/// тоннель нельзя (`AGENTS.md` §4.3).
pub(crate) fn lock<T>(what: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    match what.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
