//! Неявное соединение (underlay): одно TCP-соединение, несущее сколько
//! угодно сессий сразу.
//!
//! Термин и разделение — из эталона: «сессия» там — то, что мы называем
//! потоком приложения, а «underlay» — общее соединение под ними. Читает его
//! одна задача и раскладывает сегменты по очередям сессий; пишут все сессии
//! через один замок, как у AnyTLS (`protocols/anytls/src/session.rs`), с
//! отличием в том, что у Mieru нет отдельной команды закрытия «всего
//! потока»: закрывается ровно одна сессия, остальные не замечают.
//!
//! # Чего здесь нет
//!
//! **Управления окном отправки.** Сервер присылает в каждом сегменте
//! данных и подтверждения `unAckSeq`/`windowSize` — мы их разбираем и не
//! используем: как исправно отправлять сообщаем самим фактом, что читаем и
//! подтверждаем каждый пришедший сегмент сразу, а транспорт (TCP) и так не
//! теряет и не переупорядочивает байты. Полноценный алгоритм скользящего
//! окна, нужный эталону ради датаграммного (`UDP`) режима, здесь был бы
//! ценой без пользы — режим UDP этот крейт не реализует (см. документ
//! крейта).
//!
//! **Дополнения.** Каждый исходящий сегмент несёт дополнение нулевой длины.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use penguin_proto::stream::ProxyStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::cipher::{RecvCipher, SendCipher};
use crate::error::{MieruError, MieruResult};
use crate::keying::Key;
use crate::metadata::{self, DataAckKind, DataAckMetadata, Metadata, SessionKind, SessionMetadata};
use crate::segment;
use crate::stream::MieruStream;

/// Сколько сегментов готов принять клиент, не подтверждая их по одному.
///
/// Число из эталона (`pkg/protocol/session.go`, `maxWindowSize`) — не
/// выбор реализации: раз мы не ограничиваем себя сами (см. документ
/// модуля), разумно объявлять то же значение, что и настоящий клиент.
pub const RECEIVE_WINDOW: u16 = 4096;

/// Сколько кусков держать в очереди сессии, пока их не забрали.
const QUEUE: usize = 16;

/// Что приходит сессии из underlay.
#[derive(Debug)]
pub enum Msg {
    /// Данные.
    Data(Bytes),
    /// Сервер закрыл сессию.
    Eof,
}

/// Общее для двух сторон сессии состояние последовательности.
///
/// Делится между `Underlay` (задача чтения обновляет `next_recv` и шлёт
/// подтверждения) и потоком `MieruStream` (владелец сессии продвигает
/// `next_send` на каждой записи) — отсюда `Arc`, а не поле одного из них.
#[derive(Debug, Default)]
pub struct SessionState {
    /// Порядковый номер следующего сегмента данных, который отправим мы.
    pub next_send: AtomicU32,
    /// Порядковый номер следующего ожидаемого сегмента от собеседника.
    pub next_recv: AtomicU32,
}

/// Запись о сессии в таблице underlay.
struct SessionEntry {
    queue: mpsc::Sender<Msg>,
    state: Arc<SessionState>,
}

/// Пишущая половина: шифр и сокет под одним замком.
struct Writer {
    cipher: SendCipher,
    io: WriteHalf<Box<dyn ProxyStream>>,
}

/// Неявное соединение.
pub struct Underlay {
    /// Номер соединения в пуле. Больше — новее.
    seq: u64,
    writer: Mutex<Writer>,
    sessions: StdMutex<HashMap<u32, SessionEntry>>,
    pending_open: StdMutex<HashMap<u32, oneshot::Sender<MieruResult<()>>>>,
    next_session_id: AtomicU32,
    live: AtomicUsize,
    death: StdMutex<Option<String>>,
    idle_since: StdMutex<Instant>,
    closed: mpsc::UnboundedSender<u32>,
    tasks: StdMutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for Underlay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Underlay")
            .field("seq", &self.seq)
            .field("live", &self.live.load(Ordering::Relaxed))
            .field("dead", &self.is_dead())
            .finish()
    }
}

impl Underlay {
    /// Поднимает соединение поверх уже открытого сокета.
    pub fn start(seq: u64, io: Box<dyn ProxyStream>, key: &Key, username: Arc<str>) -> Arc<Self> {
        let (read, write) = tokio::io::split(io);
        let (closed, closed_rx) = mpsc::unbounded_channel();

        let underlay = Arc::new(Self {
            seq,
            writer: Mutex::new(Writer {
                cipher: SendCipher::new(key, &username),
                io: write,
            }),
            sessions: StdMutex::new(HashMap::new()),
            pending_open: StdMutex::new(HashMap::new()),
            next_session_id: AtomicU32::new(1),
            live: AtomicUsize::new(0),
            death: StdMutex::new(None),
            idle_since: StdMutex::new(Instant::now()),
            closed,
            tasks: StdMutex::new(Vec::new()),
        });

        let recv_cipher = RecvCipher::new(key);
        let tasks = vec![
            tokio::spawn(read_loop(Arc::downgrade(&underlay), read, recv_cipher)),
            tokio::spawn(close_loop(Arc::downgrade(&underlay), closed_rx)),
        ];
        *lock(&underlay.tasks) = tasks;
        underlay
    }

    /// Номер соединения.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Умерло ли соединение.
    pub fn is_dead(&self) -> bool {
        lock(&self.death).is_some()
    }

    /// Почему соединение умерло.
    pub fn death(&self) -> Option<String> {
        lock(&self.death).clone()
    }

    /// Сколько сессий сейчас живо на этом соединении.
    pub fn live_count(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }

    /// Свободно ли соединение для сессии сверх уже открытых.
    pub fn has_room(&self, max_sessions: usize) -> bool {
        !self.is_dead() && self.live_count() < max_sessions
    }

    /// С какого времени соединение полностью простаивает.
    pub fn idle_since(&self) -> Instant {
        *lock(&self.idle_since)
    }

    /// Открывает сессию и просит сервер открыть её у себя.
    pub async fn open_session(self: &Arc<Self>) -> Result<MieruStream, MieruError> {
        if let Some(reason) = self.death() {
            return Err(MieruError::disconnected(reason));
        }

        let id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let state = Arc::new(SessionState {
            next_send: AtomicU32::new(1),
            next_recv: AtomicU32::new(0),
        });
        let (queue, incoming) = mpsc::channel(QUEUE);
        lock(&self.sessions).insert(
            id,
            SessionEntry {
                queue,
                state: Arc::clone(&state),
            },
        );
        self.live.fetch_add(1, Ordering::AcqRel);

        let (opened, wait) = oneshot::channel();
        lock(&self.pending_open).insert(id, opened);

        let meta = SessionMetadata {
            kind: SessionKind::OpenRequest,
            timestamp_minutes: now_minutes(),
            session_id: id,
            seq: 0,
            status: 0,
            payload_len: 0,
            suffix_len: 0,
        };
        if let Err(err) = self.send(&Metadata::Session(meta), &[]).await {
            self.forget_session(id);
            lock(&self.pending_open).remove(&id);
            return Err(err);
        }

        let result = penguin_transport::deadline::handshake::<(), MieruError>(
            "открытие сессии Mieru",
            async {
                match wait.await {
                    Ok(inner) => inner,
                    Err(_) => Err(MieruError::disconnected("соединение закрылось до ответа")),
                }
            },
        )
        .await;

        match result {
            Ok(()) => Ok(MieruStream::new(Arc::clone(self), id, state, incoming)),
            Err(err) => {
                self.forget_session(id);
                Err(err)
            }
        }
    }

    /// Отправляет данные сессии.
    pub async fn send_data(
        &self,
        session_id: u32,
        state: &SessionState,
        payload: &[u8],
    ) -> MieruResult<()> {
        let payload_len = u16::try_from(payload.len())
            .map_err(|_| MieruError::malformed(format!("кусок в {} байт", payload.len())))?;
        let meta = DataAckMetadata {
            kind: DataAckKind::DataToServer,
            timestamp_minutes: now_minutes(),
            session_id,
            seq: state.next_send.fetch_add(1, Ordering::Relaxed),
            unack_seq: state.next_recv.load(Ordering::Relaxed),
            window_size: RECEIVE_WINDOW,
            fragment: 0,
            prefix_len: 0,
            payload_len,
            suffix_len: 0,
        };
        self.send(&Metadata::DataAck(meta), payload).await
    }

    /// Просит сервер закрыть сессию. Ответа не ждёт: закрывающий поток уже
    /// не будет читать его результат.
    pub async fn send_close(&self, session_id: u32) {
        let meta = SessionMetadata {
            kind: SessionKind::CloseRequest,
            timestamp_minutes: now_minutes(),
            session_id,
            seq: 0,
            status: 0,
            payload_len: 0,
            suffix_len: 0,
        };
        // Ошибку глотаем нарочно: соединение о своей смерти узнает из неё
        // само, а закрывать сессию в мёртвом соединении нечем.
        let _ = self.send(&Metadata::Session(meta), &[]).await;
    }

    /// Сообщает, что сессия закрылась у нас: сюда зовёт `Drop` потока.
    pub fn session_closed(&self, session_id: u32) {
        // Канал без границ: `Drop` не имеет права ждать.
        let _ = self.closed.send(session_id);
    }

    /// Убирает сессию из таблицы. Очередь при этом закрывается.
    fn forget_session(&self, session_id: u32) {
        lock(&self.pending_open).remove(&session_id);
        if lock(&self.sessions).remove(&session_id).is_some()
            && self.live.fetch_sub(1, Ordering::AcqRel) == 1
        {
            *lock(&self.idle_since) = Instant::now();
        }
    }

    /// Отправляет один сегмент.
    async fn send(&self, metadata: &Metadata, payload: &[u8]) -> MieruResult<()> {
        let bytes = match metadata {
            Metadata::Session(meta) => meta.encode(),
            Metadata::DataAck(meta) => meta.encode(),
        };

        let mut writer = self.writer.lock().await;
        let wire = match segment::write(&mut writer.cipher, &bytes, payload) {
            Ok(wire) => wire,
            Err(err) => {
                drop(writer);
                self.mark_dead(err.to_string());
                return Err(err);
            }
        };
        let io_result = match writer.io.write_all(&wire).await {
            Ok(()) => writer.io.flush().await,
            Err(err) => Err(err),
        };
        drop(writer);

        io_result.map_err(|err| {
            self.mark_dead(format!("запись не прошла: {err}"));
            MieruError::Io(err)
        })
    }

    /// Отправляет подтверждение о получении данных.
    async fn send_ack(&self, session_id: u32, state: &SessionState) {
        let meta = DataAckMetadata {
            kind: DataAckKind::AckFromClient,
            timestamp_minutes: now_minutes(),
            session_id,
            seq: 0,
            unack_seq: state.next_recv.load(Ordering::Relaxed),
            window_size: RECEIVE_WINDOW,
            fragment: 0,
            prefix_len: 0,
            payload_len: 0,
            suffix_len: 0,
        };
        let _ = self.send(&Metadata::DataAck(meta), &[]).await;
    }

    /// Кладёт кусок в очередь сессии. Ждёт места: терять данные нельзя.
    async fn deliver(&self, session_id: u32, msg: Msg) {
        let sender = lock(&self.sessions)
            .get(&session_id)
            .map(|entry| entry.queue.clone());
        if let Some(sender) = sender
            && sender.send(msg).await.is_err()
        {
            self.forget_session(session_id);
        }
    }

    /// Объявляет соединение мёртвым. Очереди сессий закрываются, ожидающие
    /// открытия сессии узнают об обрыве.
    fn mark_dead(&self, reason: impl Into<String>) {
        let mut death = lock(&self.death);
        if death.is_none() {
            *death = Some(reason.into());
        }
        let reason = death.clone().unwrap_or_default();
        drop(death);

        lock(&self.sessions).clear();
        self.live.store(0, Ordering::Release);
        *lock(&self.idle_since) = Instant::now();

        for (_, opened) in lock(&self.pending_open).drain() {
            let _ = opened.send(Err(MieruError::disconnected(reason.clone())));
        }
    }

    /// Закрывает свою половину соединения.
    pub async fn shutdown(&self) {
        let _ = self.writer.lock().await.io.shutdown().await;
    }
}

impl Drop for Underlay {
    fn drop(&mut self) {
        for task in lock(&self.tasks).drain(..) {
            task.abort();
        }
    }
}

/// Читает сегменты, пока соединение живо, и раскладывает их по сессиям.
async fn read_loop(
    underlay: Weak<Underlay>,
    mut read: ReadHalf<Box<dyn ProxyStream>>,
    mut recv: RecvCipher,
) {
    loop {
        match read_one_segment(&underlay, &mut read, &mut recv).await {
            Ok(true) => continue,
            Ok(false) | Err(_) => {
                if let Some(underlay) = underlay.upgrade() {
                    underlay.mark_dead("соединение с сервером Mieru потеряно");
                }
                return;
            }
        }
    }
}

/// Читает и разбирает один сегмент. `Ok(false)` — конец потока, не ошибка.
async fn read_one_segment(
    underlay: &Weak<Underlay>,
    read: &mut ReadHalf<Box<dyn ProxyStream>>,
    recv: &mut RecvCipher,
) -> MieruResult<bool> {
    let m_len = segment::metadata_block_len(recv.expects_wire_nonce());
    let mut m_block = vec![0u8; m_len];
    if !read_exact_or_eof(read, &mut m_block).await? {
        return Ok(false);
    }
    let metadata = segment::read_metadata(recv, &m_block)?;

    if !metadata::timestamp_within_range(now_minutes(), metadata.timestamp_minutes()) {
        return Err(MieruError::ClockSkew);
    }

    if metadata.prefix_len() > 0 {
        let mut discard = vec![0u8; metadata.prefix_len() as usize];
        read.read_exact(&mut discard).await?;
    }

    let payload = if metadata.payload_len() > 0 {
        let p_len = segment::payload_block_len(metadata.payload_len());
        let mut p_block = vec![0u8; p_len];
        read.read_exact(&mut p_block).await?;
        Some(segment::read_payload(recv, &p_block)?)
    } else {
        None
    };

    if metadata.suffix_len() > 0 {
        let mut discard = vec![0u8; metadata.suffix_len() as usize];
        read.read_exact(&mut discard).await?;
    }

    let Some(underlay) = underlay.upgrade() else {
        return Ok(false);
    };
    dispatch(&underlay, metadata, payload).await;
    Ok(true)
}

/// Отдаёт разобранный сегмент нужной сессии.
async fn dispatch(underlay: &Arc<Underlay>, metadata: Metadata, payload: Option<Vec<u8>>) {
    match metadata {
        Metadata::Session(meta) => dispatch_session_control(underlay, meta, payload).await,
        Metadata::DataAck(meta) => dispatch_data_ack(underlay, meta, payload).await,
    }
}

async fn dispatch_session_control(
    underlay: &Arc<Underlay>,
    meta: SessionMetadata,
    payload: Option<Vec<u8>>,
) {
    match meta.kind {
        SessionKind::OpenResponse => {
            if let Some(opened) = lock(&underlay.pending_open).remove(&meta.session_id) {
                let result = match meta.status {
                    metadata::STATUS_OK => Ok(()),
                    metadata::STATUS_QUOTA_EXHAUSTED => Err(MieruError::QuotaExhausted),
                    other => Err(MieruError::malformed(format!(
                        "неизвестный код ответа на открытие сессии: {other}"
                    ))),
                };
                let _ = opened.send(result);
            }
            if let Some(payload) = payload {
                underlay
                    .deliver(meta.session_id, Msg::Data(payload.into()))
                    .await;
            }
        }
        SessionKind::CloseRequest | SessionKind::CloseResponse => {
            underlay.deliver(meta.session_id, Msg::Eof).await;
            underlay.forget_session(meta.session_id);
        }
        // Сервер не должен присылать клиенту запрос открыть сессию — это
        // наша реплика. Пришедший всё равно не роняет соединение: длина
        // объявлена верно, читать его можно и дальше.
        SessionKind::OpenRequest => {
            tracing::debug!(
                session = meta.session_id,
                "неожиданный openSessionRequest от сервера"
            );
        }
    }
}

async fn dispatch_data_ack(
    underlay: &Arc<Underlay>,
    meta: DataAckMetadata,
    payload: Option<Vec<u8>>,
) {
    let state = lock(&underlay.sessions)
        .get(&meta.session_id)
        .map(|entry| Arc::clone(&entry.state));
    let Some(state) = state else {
        return;
    };

    match meta.kind {
        DataAckKind::DataToClient => {
            if let Some(payload) = payload {
                state.next_recv.fetch_add(1, Ordering::Relaxed);
                underlay
                    .deliver(meta.session_id, Msg::Data(payload.into()))
                    .await;
                underlay.send_ack(meta.session_id, &state).await;
            }
        }
        // Подтверждения от сервера мы разбираем, но не используем для
        // управления потоком — см. документ модуля.
        DataAckKind::AckFromServer => {}
        // Эти два вида идут от клиента к серверу; получить их обратно —
        // аномалия на стороне сервера, а не повод рвать соединение.
        DataAckKind::DataToServer | DataAckKind::AckFromClient => {
            tracing::debug!(session = meta.session_id, kind = ?meta.kind, "неожиданное направление сегмента");
        }
    }
}

/// Закрывает сессии, о которых сказал их `Drop`.
async fn close_loop(underlay: Weak<Underlay>, mut closed: mpsc::UnboundedReceiver<u32>) {
    while let Some(session_id) = closed.recv().await {
        let Some(underlay) = underlay.upgrade() else {
            return;
        };
        underlay.forget_session(session_id);
        if underlay.is_dead() {
            continue;
        }
        underlay.send_close(session_id).await;
    }
}

/// Минут с начала эпохи по системным часам. Смещение времени назад (часы
/// перевели) даёт `0`, а не панику — на пути соединения паниковать нельзя
/// (`AGENTS.md` §4.3), и это лишь на минуту исказит проверку часов.
fn now_minutes() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    u32::try_from(secs / 60).unwrap_or(u32::MAX)
}

/// Читает ровно `buf.len()` байт, либо сообщает, что поток кончился ровно
/// на границе сегмента — это конец соединения, а не ошибка.
async fn read_exact_or_eof(
    read: &mut ReadHalf<Box<dyn ProxyStream>>,
    buf: &mut [u8],
) -> MieruResult<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = read.read(&mut buf[filled..]).await?;
        if n == 0 {
            return if filled == 0 {
                Ok(false)
            } else {
                Err(MieruError::malformed(
                    "соединение оборвалось внутри сегмента",
                ))
            };
        }
        filled += n;
    }
    Ok(true)
}

/// Берёт замок, не роняя соединение из-за чужой паники.
fn lock<T>(what: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    match what.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
