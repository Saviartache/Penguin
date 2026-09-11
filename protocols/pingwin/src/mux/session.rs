//! Сессия: разбор кадров, очереди потоков и общая запись.
//!
//! ```text
//!   поток 1 ─┐                                  ┌─► очередь 1 ─► приложение
//!   поток 2 ─┼─► очередь ─► задача записи ─► сокет ─► задача разбора ─┤
//!   поток 3 ─┘                                  └─► очередь 3 ─► приложение
//! ```
//!
//! Две задачи на сессию, и обе владеют своей половиной сокета единолично.
//! Пишущая — не роскошь: запись, начатая прямо из потока приложения,
//! отменяется вместе с ним и оставляет на проводе половину записи. Подробнее —
//! в документе `write_loop`.
//!
//! # Кто кого держит
//!
//! Сессию держат снаружи (пул у клиента, задача соединения у сервера), а её
//! собственные задачи — [`Weak`]: иначе сессия не умерла бы никогда. Потоки
//! держат [`Arc`] на сессию, потому что закрывающийся поток обязан успеть
//! сказать об этом собеседнику.
//!
//! # Почему очередь потока ограничена
//!
//! Поток, из которого не читают, останавливает **всю** сессию: задача разбора
//! ждёт места в его очереди. Это не недосмотр, а выбор в пользу простоты:
//! окно на каждый поток — это второй протокол внутри первого. Лечится это
//! тем, что движок читает обе стороны соединения одновременно и потому
//! никогда не перестаёт забирать данные.
//!
//! Датаграммы — исключение: их очередь не ждёт, а теряет посылки. Так
//! устроен UDP, и один медленный канал не вправе останавливать сессию.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_proto::stream::ProxyStream;
use penguin_transport::addr::socks;
use penguin_transport::aead::{Algorithm, Cipher};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::error::{PingwinError, PingwinResult};
use crate::records::{RecordReader, RecordWriter};
use crate::wire::frame;
use crate::wire::keys::SessionKeys;
use crate::wire::padding::Padding;
use crate::wire::record;

/// Соединение, поверх которого живёт сессия.
pub type Carrier = Box<dyn ProxyStream>;

/// Номер первого потока.
///
/// Ноль занят кадрами, которые не принадлежат никакому потоку (`PING`,
/// `PAD`), — и он же означает «поток не назван» у собеседника, который
/// прислал мусор.
pub const FIRST_SID: u32 = 1;

/// Сколько кусков держать для потока, пока их не забрали.
///
/// Это и есть окно приёма, хотя окном нигде не называется: заполнилась
/// очередь — задача разбора встала на ней, перестала читать сокет, и
/// собеседник упёрся в окно TCP.
///
/// Сто двадцать восемь кусков — два мегабайта на поток в пределе и ноль, пока
/// поток простаивает.
const QUEUE: usize = 128;

/// Сколько кадров ждут отправки, прежде чем пишущий начнёт притормаживать.
///
/// Число маленькое намеренно, и это не экономия памяти. Всё, что мы отдали
/// ядру, стоит в очереди отправки и ждёт своей очереди в сети; чем длиннее
/// эта очередь, тем позже уходит **следующий** кадр — чей угодно, хоть
/// нажатия в ssh. Замер на живой линии: набив очередь на семьсот килобайт,
/// мы подняли задержку соединения с девяноста пяти миллисекунд до
/// четырёхсот двадцати. TCP считает скорость как окно, делённое на задержку,
/// — то есть длинная очередь portит и то, и другое разом.
///
/// Шестнадцать кадров — это четверть мегабайта в полёте. Хватает, чтобы
/// сокет не простаивал, и мало, чтобы очередь не превращалась в задержку.
const OUTGOING: usize = 16;

/// Как часто спрашивать собеседника, жив ли он.
const PING_EVERY: Duration = Duration::from_secs(30);

/// Через сколько молчания считать сессию мёртвой.
///
/// Три пропущенных проверки: одна потерянная посылка — обычное дело, три
/// подряд означают, что отвечать некому.
const SILENCE: Duration = Duration::from_secs(95);

/// Кто мы в этой сессии.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Открывает потоки.
    Client,
    /// Принимает их.
    Server,
}

/// Что приходит потоку из сессии.
#[derive(Debug)]
pub enum Msg {
    /// Данные.
    Data(Bytes),
    /// Собеседник больше ничего не пришлёт.
    Eof,
    /// Поток оборван.
    Failed(String),
}

/// Просьба открыть поток — то, что сервер получает от клиента.
pub struct StreamRequest {
    session: Arc<Session>,
    sid: u32,
    target: SocketAddress,
    incoming: mpsc::Receiver<Msg>,
}

impl std::fmt::Debug for StreamRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamRequest")
            .field("sid", &self.sid)
            .field("target", &self.target.to_wire())
            .finish()
    }
}

impl StreamRequest {
    /// Куда клиент просит соединиться.
    pub fn target(&self) -> &SocketAddress {
        &self.target
    }

    /// Соглашается: клиент получит подтверждение, а вызывающий — поток.
    pub async fn accept(self) -> PingwinResult<super::PingwinStream> {
        self.session.send(frame::OPEN_OK, self.sid, &[]).await?;
        Ok(super::PingwinStream::new(
            Arc::clone(&self.session),
            self.sid,
            self.incoming,
        ))
    }

    /// Отказывает: клиент узнает причину, а не тайм-аут.
    pub async fn reject(self, reason: &str) -> PingwinResult<()> {
        self.session.forget(self.sid);
        self.session
            .send(frame::OPEN_ERR, self.sid, reason.as_bytes())
            .await
    }
}

/// Просьба открыть датаграммный канал.
pub struct DatagramRequest {
    session: Arc<Session>,
    sid: u32,
    incoming: mpsc::Receiver<(Bytes, SocketAddress)>,
}

impl std::fmt::Debug for DatagramRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatagramRequest")
            .field("sid", &self.sid)
            .finish()
    }
}

impl DatagramRequest {
    /// Соглашается и отдаёт канал.
    pub async fn accept(self) -> PingwinResult<super::PingwinDatagram> {
        self.session.send(frame::OPEN_OK, self.sid, &[]).await?;
        Ok(super::PingwinDatagram::new(
            Arc::clone(&self.session),
            self.sid,
            self.incoming,
        ))
    }
}

/// Что сервер получает от клиента.
#[derive(Debug)]
pub enum Incoming {
    /// Просьба открыть поток.
    Stream(Box<StreamRequest>),
    /// Просьба открыть датаграммный канал.
    Datagram(Box<DatagramRequest>),
}

/// Сессия Pingwin.
pub struct Session {
    role: Role,
    /// Очереди потоков.
    streams: StdMutex<HashMap<u32, mpsc::Sender<Msg>>>,
    /// Очереди датаграммных каналов.
    datagrams: StdMutex<HashMap<u32, mpsc::Sender<(Bytes, SocketAddress)>>>,
    /// Кадры, ждущие отправки.
    ///
    /// Единственный путь наружу: сокетом владеет отдельная задача, и никто,
    /// кроме неё, в него не пишет. Почему так — в документе [`write_loop`].
    outgoing: mpsc::Sender<Vec<u8>>,
    /// Номер следующего потока. Нумерует только клиент.
    next_sid: AtomicU32,
    /// Почему сессия умерла. Пусто — жива.
    death: StdMutex<Option<String>>,
    /// Когда в последний раз что-нибудь пришло, секунд от рождения.
    last_seen: AtomicU64,
    /// Момент рождения — точка отсчёта для [`Self::last_seen`].
    born: Instant,
    /// Кто ждёт ответа на проверку живости.
    ///
    /// Один на сессию, и больше не нужно: замер задержки делают по просьбе
    /// человека, а не в цикле. Пришёл второй, пока не ответили первому, —
    /// первый останется без ответа и упрётся в свой срок.
    pong: StdMutex<Option<oneshot::Sender<()>>>,
    /// Ссылка на себя: её раздают просьбам открыть поток.
    ///
    /// Иначе не обойтись: разбор кадров идёт из задачи, у которой на руках
    /// только [`Weak`], а `&self` про `Arc` ничего не знает.
    me: StdMutex<Weak<Session>>,
    /// Задачи сессии.
    tasks: StdMutex<Vec<JoinHandle<()>>>,
    /// Сессия уже закрывалась.
    closed: AtomicBool,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("role", &self.role)
            .field("dead", &self.is_dead())
            .field("streams", &self.stream_count())
            .finish()
    }
}

impl Session {
    /// Поднимает сессию поверх уже установленного соединения.
    ///
    /// `early` — кадры, приехавшие вместе с приветствием (0-RTT). Они
    /// разбираются первыми, как будто пришли обычным путём.
    ///
    /// Возвращает сессию и очередь входящих просьб. У клиента очередь пуста
    /// всегда: сервер потоков не открывает.
    pub fn start(
        carrier: Carrier,
        role: Role,
        keys: &SessionKeys,
        algorithm: Algorithm,
        early: Option<Vec<u8>>,
    ) -> PingwinResult<(Arc<Self>, mpsc::Receiver<Incoming>)> {
        let (send_key, recv_key, send_pad) = match role {
            Role::Client => (&keys.c2s, &keys.s2c, keys.pad_c2s),
            Role::Server => (&keys.s2c, &keys.c2s, keys.pad_s2c),
        };

        let (read_half, write_half) = tokio::io::split(carrier);
        let writer = RecordWriter::new(
            write_half,
            Cipher::new(algorithm, send_key)?,
            Padding::from_seed(&send_pad),
        );
        let reader = RecordReader::new(read_half, Cipher::new(algorithm, recv_key)?);

        let (incoming_tx, incoming_rx) = mpsc::channel(QUEUE);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(OUTGOING);
        let session = Arc::new(Self {
            role,
            streams: StdMutex::new(HashMap::new()),
            datagrams: StdMutex::new(HashMap::new()),
            outgoing: outgoing_tx,
            next_sid: AtomicU32::new(FIRST_SID),
            death: StdMutex::new(None),
            last_seen: AtomicU64::new(0),
            born: Instant::now(),
            pong: StdMutex::new(None),
            me: StdMutex::new(Weak::new()),
            tasks: StdMutex::new(Vec::new()),
            closed: AtomicBool::new(false),
        });
        if let Ok(mut me) = session.me.lock() {
            *me = Arc::downgrade(&session);
        }

        let reading = tokio::spawn({
            let weak = Arc::downgrade(&session);
            async move { read_loop(weak, reader, incoming_tx, early).await }
        });
        let writing = tokio::spawn({
            let weak = Arc::downgrade(&session);
            async move { write_loop(weak, writer, outgoing_rx).await }
        });
        let pinging = tokio::spawn({
            let weak = Arc::downgrade(&session);
            async move { ping_loop(weak).await }
        });
        if let Ok(mut tasks) = session.tasks.lock() {
            tasks.push(reading);
            tasks.push(writing);
            tasks.push(pinging);
        }

        Ok((session, incoming_rx))
    }

    /// Кадр `OPEN` для первого потока — тот, что уезжает ранними данными.
    ///
    /// Отдельная функция, а не метод: кадр собирается **до** того, как сессия
    /// появилась на свет, — в этом весь смысл 0-RTT.
    pub fn early_open(target: &SocketAddress) -> PingwinResult<(u32, Vec<u8>)> {
        let mut request = Vec::new();
        socks::encode(target, &mut request)?;
        Ok((FIRST_SID, frame::encode(frame::OPEN, FIRST_SID, &request)?))
    }

    /// Открывает поток до `target`. Только у клиента.
    ///
    /// Подтверждения **не ждёт**. Раньше ждал — и это стоило целого оборота на
    /// каждом соединении: приложение не могло послать ни байта, пока сервер не
    /// сходит к цели и не ответит. На линии со ста миллисекундами задержки
    /// открытие вкладки браузера теряло на этом секунду.
    ///
    /// Отказ от этого ничего не ломает: `OPEN_ERR` от сервера приезжает в ту
    /// же очередь, что и данные, и превращается в ошибку первого же чтения или
    /// записи — то есть приходит туда, где приложение и так проверяет исход.
    /// Так же устроен любой мультиплексор, который не платит оборотом за
    /// открытие: запрос и первые данные уезжают одной посылкой.
    pub async fn open_tcp(
        self: &Arc<Self>,
        target: &SocketAddress,
    ) -> PingwinResult<super::PingwinStream> {
        let sid = self.take_sid();
        let incoming = self.register_stream(sid);
        let mut request = Vec::new();
        socks::encode(target, &mut request)?;
        self.send(frame::OPEN, sid, &request).await?;
        Ok(super::PingwinStream::new(Arc::clone(self), sid, incoming))
    }

    /// Занимает номер, выданный до рождения сессии.
    ///
    /// Зовётся сразу после [`Self::start`] и **до** того, как сессию увидит
    /// кто-то ещё: иначе соседнее соединение успеет взять тот же номер, и два
    /// потока станут делить одну очередь.
    pub fn reserve(&self, sid: u32) {
        self.next_sid
            .fetch_max(sid.saturating_add(1), Ordering::Relaxed);
    }

    /// Заводит поток, чей `OPEN` уже уехал вместе с приветствием.
    pub fn adopt_early(self: &Arc<Self>, sid: u32) -> super::PingwinStream {
        self.reserve(sid);
        let incoming = self.register_stream(sid);
        super::PingwinStream::new(Arc::clone(self), sid, incoming)
    }

    /// Открывает датаграммный канал. Только у клиента.
    ///
    /// Подтверждения не ждёт — по той же причине, что и [`Self::open_tcp`].
    pub async fn open_udp(self: &Arc<Self>) -> PingwinResult<super::PingwinDatagram> {
        let sid = self.take_sid();
        let (tx, incoming) = mpsc::channel(QUEUE);
        if let Ok(mut datagrams) = self.datagrams.lock() {
            datagrams.insert(sid, tx);
        }
        self.send(frame::UDP_BIND, sid, &[]).await?;
        Ok(super::PingwinDatagram::new(Arc::clone(self), sid, incoming))
    }

    /// Ставит кадр в очередь на отправку.
    ///
    /// Сокета отсюда не видно: им владеет [`write_loop`], и это не украшение
    /// архитектуры, а лечение конкретной ошибки. Пока запись шла прямо
    /// отсюда, отменённая задача — брошенный поток, оборванная загрузка —
    /// роняла `write_all` посреди записи, и на проводе оставалась её
    /// половина. Дальше не сходилась метка **следующей** записи, и умирала
    /// вся сессия: одно закрытое окно браузера обрывало все остальные.
    ///
    /// Постановка в очередь такой беды не знает: она либо случилась целиком,
    /// либо не случилась вовсе.
    pub(crate) async fn send(&self, cmd: u8, sid: u32, data: &[u8]) -> PingwinResult<()> {
        if let Some(reason) = self.death_reason() {
            return Err(PingwinError::disconnected(reason));
        }

        let framed = frame::encode(cmd, sid, data)?;
        self.outgoing
            .send(framed)
            .await
            .map_err(|_| PingwinError::disconnected("сессия закрылась"))
    }

    /// Убирает поток из таблиц. Зовётся при закрытии с обеих сторон.
    pub(crate) fn forget(&self, sid: u32) {
        if let Ok(mut streams) = self.streams.lock() {
            streams.remove(&sid);
        }
        if let Ok(mut datagrams) = self.datagrams.lock() {
            datagrams.remove(&sid);
        }
    }

    /// Сколько потоков живо.
    pub fn stream_count(&self) -> usize {
        self.streams
            .lock()
            .map(|streams| streams.len())
            .unwrap_or(0)
    }

    /// Сессия мертва.
    pub fn is_dead(&self) -> bool {
        self.death_reason().is_some()
    }

    /// Меряет задержку до собеседника проверкой живости.
    ///
    /// `None` — ответа не дождались; сессию это не убивает: за её живостью
    /// следит `ping_loop`, и один потерянный ответ ему не повод.
    pub async fn round_trip(&self, limit: Duration) -> Option<Duration> {
        let (tx, rx) = oneshot::channel();
        *self.pong.lock().ok()? = Some(tx);

        let started = Instant::now();
        self.send(frame::PING, 0, &[]).await.ok()?;
        tokio::time::timeout(limit, rx).await.ok()?.ok()?;
        Some(started.elapsed())
    }

    fn answer_pong(&self) {
        let waiting = self.pong.lock().ok().and_then(|mut pong| pong.take());
        if let Some(waiting) = waiting {
            let _ = waiting.send(());
        }
    }

    /// Закрывает сессию: гасит задачи и закрывает соединение.
    ///
    /// Соединение закрывается тем, что задачи бросают свои половины сокета:
    /// обе половины исчезают — исчезает и сокет. Отдельного `shutdown` здесь
    /// нет и быть не может, потому что писать в сокет отсюда некому: им
    /// владеет `write_loop`.
    pub async fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.die("сессия закрыта");
        let tasks = self
            .tasks
            .lock()
            .map(|mut tasks| tasks.drain(..).collect::<Vec<_>>())
            .unwrap_or_default();
        for task in tasks {
            task.abort();
        }
    }

    fn take_sid(&self) -> u32 {
        self.next_sid.fetch_add(1, Ordering::Relaxed)
    }

    fn register_stream(&self, sid: u32) -> mpsc::Receiver<Msg> {
        let (tx, rx) = mpsc::channel(QUEUE);
        if let Ok(mut streams) = self.streams.lock() {
            streams.insert(sid, tx);
        }
        rx
    }

    fn death_reason(&self) -> Option<String> {
        self.death.lock().ok().and_then(|death| death.clone())
    }

    /// Объявляет сессию мёртвой и распускает всех, кто её ждёт.
    fn die(&self, reason: impl Into<String>) {
        let reason = reason.into();
        match self.death.lock() {
            Ok(mut death) if death.is_none() => *death = Some(reason.clone()),
            Ok(_) => return,
            Err(_) => return,
        }

        if let Ok(mut streams) = self.streams.lock() {
            for (_, queue) in streams.drain() {
                let _ = queue.try_send(Msg::Failed(reason.clone()));
            }
        }
        if let Ok(mut datagrams) = self.datagrams.lock() {
            datagrams.clear();
        }
    }

    /// Разбирает одну расшифрованную запись.
    async fn dispatch_record(&self, plain: &[u8], incoming: &mpsc::Sender<Incoming>) {
        self.last_seen
            .store(self.born.elapsed().as_secs(), Ordering::Relaxed);

        for parsed in frame::Frames::new(plain) {
            match parsed {
                Ok((header, body)) => self.dispatch(header, body, incoming).await,
                Err(err) => {
                    self.die(err.to_string());
                    return;
                }
            }
        }
    }

    async fn dispatch(
        &self,
        header: frame::Header,
        body: &[u8],
        incoming: &mpsc::Sender<Incoming>,
    ) {
        match header.cmd {
            frame::PAD => {}
            frame::PONG => self.answer_pong(),
            frame::PING => self.reply_pong(),
            frame::OPEN => self.on_open(header.sid, body, incoming).await,
            frame::UDP_BIND => self.on_udp_bind(header.sid, incoming).await,
            // Подтверждения никто не ждёт: поток отдан приложению сразу, а
            // `OPEN_OK` — только знак, что цель ответила.
            frame::OPEN_OK => {}
            // Отказ приезжает туда же, куда приехали бы данные, и становится
            // ошибкой первого же чтения.
            frame::OPEN_ERR => {
                let reason = String::from_utf8_lossy(body).into_owned();
                self.push(header.sid, Msg::Failed(reason)).await;
                self.forget(header.sid);
            }
            frame::DATA => {
                self.push(header.sid, Msg::Data(Bytes::copy_from_slice(body)))
                    .await;
            }
            frame::FIN => self.push(header.sid, Msg::Eof).await,
            frame::RST => {
                let reason = String::from_utf8_lossy(body).into_owned();
                self.push(header.sid, Msg::Failed(reason)).await;
                self.forget(header.sid);
            }
            frame::UDP => self.on_udp(header.sid, body),
            other => tracing::debug!(cmd = other, "неизвестный кадр — пропущен"),
        }
    }

    /// Отвечает на проверку живости.
    ///
    /// Отдельной задачей, а не здесь же: разбор записи не имеет права ждать
    /// на замке записи. Тот, кто держит замок, может ждать места в сокете, а
    /// место освободится только тогда, когда собеседник прочитает, — то есть
    /// когда наш разбор пойдёт дальше. Это и есть взаимная блокировка.
    fn reply_pong(&self) {
        let Some(session) = self.me() else { return };
        tokio::spawn(async move {
            let _ = session.send(frame::PONG, 0, &[]).await;
        });
    }

    async fn on_open(&self, sid: u32, body: &[u8], incoming: &mpsc::Sender<Incoming>) {
        if self.role != Role::Server {
            self.die("клиент получил просьбу открыть поток");
            return;
        }
        let target = match socks::decode(body) {
            Ok(Some((target, _))) => target,
            Ok(None) | Err(_) => {
                self.die("адрес в кадре OPEN не разбирается");
                return;
            }
        };
        let (tx, rx) = mpsc::channel(QUEUE);
        if let Ok(mut streams) = self.streams.lock() {
            streams.insert(sid, tx);
        }
        let Some(session) = self.me() else { return };
        let request = StreamRequest {
            session,
            sid,
            target,
            incoming: rx,
        };
        if incoming
            .send(Incoming::Stream(Box::new(request)))
            .await
            .is_err()
        {
            self.forget(sid);
        }
    }

    async fn on_udp_bind(&self, sid: u32, incoming: &mpsc::Sender<Incoming>) {
        if self.role != Role::Server {
            self.die("клиент получил просьбу открыть датаграммный канал");
            return;
        }
        let (tx, rx) = mpsc::channel(QUEUE);
        if let Ok(mut datagrams) = self.datagrams.lock() {
            datagrams.insert(sid, tx);
        }
        let Some(session) = self.me() else { return };
        let request = DatagramRequest {
            session,
            sid,
            incoming: rx,
        };
        if incoming
            .send(Incoming::Datagram(Box::new(request)))
            .await
            .is_err()
        {
            self.forget(sid);
        }
    }

    fn on_udp(&self, sid: u32, body: &[u8]) {
        let Ok(Some((from, used))) = socks::decode(body) else {
            tracing::debug!(sid, "датаграмма без разбираемого адреса — выброшена");
            return;
        };
        let payload = Bytes::copy_from_slice(&body[used..]);
        let queue = self
            .datagrams
            .lock()
            .ok()
            .and_then(|queues| queues.get(&sid).cloned());
        if let Some(queue) = queue {
            // Датаграмма — не поток: потерять её законно, а ждать на ней
            // нельзя, иначе один медленный канал остановит всю сессию.
            let _ = queue.try_send((payload, from));
        }
    }

    /// Кладёт сообщение в очередь потока.
    ///
    /// Ждёт места намеренно (см. документ модуля): выбросить кусок потока —
    /// значит отдать приложению неполные данные и промолчать об этом.
    async fn push(&self, sid: u32, message: Msg) {
        let queue = self
            .streams
            .lock()
            .ok()
            .and_then(|streams| streams.get(&sid).cloned());
        if let Some(queue) = queue
            && queue.send(message).await.is_err()
        {
            // Приложение бросило поток и не читает: собеседнику об этом
            // скажет `Drop` самого потока, здесь достаточно забыть очередь.
            self.forget(sid);
        }
    }

    fn me(&self) -> Option<Arc<Session>> {
        self.me.lock().ok().and_then(|me| me.upgrade())
    }
}

/// Единственный, кто пишет в сокет.
///
/// # Зачем отдельная задача
///
/// Ради двух вещей сразу, и первая — правильность. Запись, начатая прямо из
/// потока приложения, отменяется вместе с ним: брошенная вкладка роняет
/// `write_all` посреди записи, на проводе остаётся её половина, и у
/// собеседника не сходится метка **следующей** записи. Одно закрытое окно
/// обрывало всю сессию. Задача, которой никто не владеет, отмениться не может.
///
/// Вторая — скорость. Пока предыдущая запись уходит в сокет, кадры копятся, и
/// следующая забирает их все разом. Нагрузка сама собирается в пачки ровно
/// тогда, когда её много, и не добавляет ни миллисекунды ожидания, когда её
/// мало: если в очереди один кадр, он уходит один.
///
/// Кадр при этом не режется границей записи — разбор внутри записи идёт кадр
/// за кадром, и половина кадра в конце для него обрыв, а не «конец пачки».
async fn write_loop(
    session: Weak<Session>,
    mut writer: RecordWriter<WriteHalf<Carrier>>,
    mut outgoing: mpsc::Receiver<Vec<u8>>,
) {
    let mut batch: Vec<u8> = Vec::with_capacity(record::MAX_PLAIN);
    // Кадр, который не влез в предыдущую пачку и открывает следующую.
    let mut carry: Option<Vec<u8>> = None;

    loop {
        let first = match carry.take() {
            Some(frame) => frame,
            None => match outgoing.recv().await {
                Some(frame) => frame,
                None => break,
            },
        };

        batch.clear();
        batch.extend_from_slice(&first);
        while let Ok(next) = outgoing.try_recv() {
            if batch.len() + next.len() > record::MAX_PLAIN {
                carry = Some(next);
                break;
            }
            batch.extend_from_slice(&next);
        }

        if let Err(err) = writer.write(&mut batch).await {
            if let Some(session) = session.upgrade() {
                session.die(err.to_string());
            }
            return;
        }
    }

    let _ = writer.shutdown().await;
}

async fn read_loop(
    session: Weak<Session>,
    mut reader: RecordReader<ReadHalf<Carrier>>,
    incoming: mpsc::Sender<Incoming>,
    early: Option<Vec<u8>>,
) {
    if let Some(early) = early {
        let Some(alive) = session.upgrade() else {
            return;
        };
        alive.dispatch_record(&early, &incoming).await;
    }

    loop {
        let record = reader.read().await;
        let Some(alive) = session.upgrade() else {
            return;
        };
        match record {
            Ok(plain) => {
                // Отметка живости ставится **до** разбора, а не внутри него.
                // Разбор умеет ждать: очередь потока, из которого приложение
                // читает медленно, придерживает его сколько угодно долго. Со
                // старой отметкой такое ожидание выглядело молчанием
                // собеседника, и проверка живости убивала сессию посреди
                // работающей загрузки.
                alive
                    .last_seen
                    .store(alive.born.elapsed().as_secs(), Ordering::Relaxed);
                alive.dispatch_record(&plain, &incoming).await;
            }
            Err(err) => {
                alive.die(err.to_string());
                return;
            }
        }
    }
}

async fn ping_loop(session: Weak<Session>) {
    let mut ticker = tokio::time::interval(PING_EVERY);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let Some(session) = session.upgrade() else {
            return;
        };

        let now = session.born.elapsed().as_secs();
        let silent = now.saturating_sub(session.last_seen.load(Ordering::Relaxed));
        if silent > SILENCE.as_secs() {
            session.die("собеседник молчит");
            return;
        }
        if session.send(frame::PING, 0, &[]).await.is_err() {
            return;
        }
    }
}
