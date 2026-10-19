//! Задача-водитель: единственный владелец сокета и сеанса (без `Mutex`);
//! `send`/`recv` передают байты через каналы. Обфускация AmneziaWG
//! (`crate::obfs`), если задана, оборачивает исходящие и классифицирует входящие
//! датаграммы; без неё путь байт в байт прежний.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use penguin_proto::random;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use crate::crypto::constants::{
    INITIATION_MESSAGE_LEN, MESSAGE_COOKIE_REPLY, MESSAGE_INITIATION, MESSAGE_RESPONSE,
    MESSAGE_TRANSPORT_DATA, REKEY_ATTEMPT_TIME, REKEY_TIMEOUT, REKEY_TIMEOUT_JITTER_MAX_MS,
};
use crate::crypto::handshake::{PendingHandshake, StaticKeys, consume_response, create_initiation};
use crate::crypto::session::Session;
use crate::error::WireguardResult;
use crate::frame::{response, transport};
use crate::obfs::{MsgKind, Obfuscation};

/// Буфер одного чтения сокета: с запасом больше любого MTU.
const RECV_BUFFER_LEN: usize = 2048;

/// Не будить задачу чаще, чем раз в это время.
const MIN_WAKE: Duration = Duration::from_secs(1);

/// Всё, что нужно задаче-водителю.
pub(super) struct Handles {
    pub socket: Arc<UdpSocket>,
    pub static_keys: Arc<StaticKeys>,
    pub reserved: [u8; 3],
    pub obfs: Option<Obfuscation>,
    pub keepalive: Option<Duration>,
    pub session: Session,
    /// Время оборота последнего рукопожатия, мс.
    pub handshake_millis: Arc<AtomicU32>,
    pub outbound_rx: mpsc::Receiver<Bytes>,
    pub inbound_tx: mpsc::Sender<Bytes>,
    pub shutdown_rx: oneshot::Receiver<()>,
}

/// Незавершённая попытка обновить рукопожатие.
struct RekeyAttempt {
    pending: PendingHandshake,
    /// Начало серии повторов; предел серии - [`REKEY_ATTEMPT_TIME`].
    first_sent_at: Instant,
    last_sent_at: Instant,
    /// Через сколько после `last_sent_at` повторить, если ответа нет.
    retry_after: Duration,
}

impl RekeyAttempt {
    fn next_due(&self) -> Instant {
        (self.last_sent_at + self.retry_after).min(self.first_sent_at + REKEY_ATTEMPT_TIME)
    }
}

/// Класс входящей датаграммы после классификации.
enum Incoming {
    Transport,
    Response,
    Cookie,
    Other,
}

/// Первые 4 байта инициации: обычный заголовок или магический `H1` от обфускатора.
fn init_header(reserved: [u8; 3], obfs: &Option<Obfuscation>) -> [u8; 4] {
    match obfs {
        Some(o) => o.init_header(),
        None => [MESSAGE_INITIATION, reserved[0], reserved[1], reserved[2]],
    }
}

/// Отправляет инициацию: при обфускации сперва сигнатуры и junk, затем кадр с padding.
async fn send_initiation_datagram(
    socket: &UdpSocket,
    message: &[u8; INITIATION_MESSAGE_LEN],
    obfs: &Option<Obfuscation>,
) -> std::io::Result<()> {
    match obfs {
        Some(o) => {
            for packet in o.prelude() {
                socket.send(&packet).await?;
            }
            socket.send(&o.wrap_initiation(message)).await?;
        }
        None => {
            socket.send(message).await?;
        }
    }
    Ok(())
}

/// Нули к открытому тексту пакета данных (AWG 3); без обфускации — ни одного.
fn data_padding(obfs: &mut Option<Obfuscation>, plaintext_len: usize) -> usize {
    obfs.as_mut()
        .map_or(0, |o| o.transport_padding(plaintext_len))
}

/// Классифицирует датаграмму и возвращает границы кадра (padding и защита сняты).
fn classify_incoming(datagram: &mut [u8], obfs: &Option<Obfuscation>) -> (Incoming, usize, usize) {
    match obfs {
        Some(o) => match o.open(datagram) {
            Some(c) => {
                let kind = match c.kind {
                    MsgKind::Transport => Incoming::Transport,
                    MsgKind::Response => Incoming::Response,
                    MsgKind::Cookie => Incoming::Cookie,
                };
                (kind, c.start, c.end)
            }
            None => (Incoming::Other, 0, 0),
        },
        None => {
            let kind = match datagram.first().copied() {
                Some(MESSAGE_TRANSPORT_DATA) => Incoming::Transport,
                Some(MESSAGE_RESPONSE) => Incoming::Response,
                Some(MESSAGE_COOKIE_REPLY) => Incoming::Cookie,
                _ => Incoming::Other,
            };
            (kind, 0, datagram.len())
        }
    }
}

/// Рукопожатие с нуля: инициация повторяется, пока сервер не ответит.
/// Вместе с сеансом — время оборота последней инициации.
pub(super) async fn initial_handshake(
    socket: &UdpSocket,
    keys: &StaticKeys,
    reserved: [u8; 3],
    obfs: &Option<Obfuscation>,
) -> WireguardResult<(Session, u32)> {
    let mut buf = [0u8; RECV_BUFFER_LEN];
    loop {
        let (message, pending) = create_initiation(keys, init_header(reserved, obfs));
        send_initiation_datagram(socket, &message, obfs).await?;
        let sent_at = Instant::now();

        let timeout = REKEY_TIMEOUT + jitter();
        match tokio::time::timeout(timeout, wait_for_response(socket, &mut buf, obfs)).await {
            Ok(Ok((start, end))) => {
                if let Ok(keys_out) = consume_response(keys, pending, &buf[start..end]) {
                    return Ok((Session::new(keys_out), millis_since(sent_at)));
                }
            }
            Ok(Err(io_error)) => return Err(io_error.into()),
            Err(_elapsed) => {}
        }
    }
}

/// Ждёт пакет «ответ на рукопожатие», возвращает границы кадра; остальное отбрасывает.
async fn wait_for_response(
    socket: &UdpSocket,
    buf: &mut [u8],
    obfs: &Option<Obfuscation>,
) -> std::io::Result<(usize, usize)> {
    loop {
        let len = socket.recv(buf).await?;
        if let (Incoming::Response, start, end) = classify_incoming(&mut buf[..len], obfs) {
            return Ok((start, end));
        }
    }
}

fn millis_since(moment: Instant) -> u32 {
    u32::try_from(moment.elapsed().as_millis()).unwrap_or(u32::MAX)
}

/// Сдвиг срока повтора (`REKEY_TIMEOUT_JITTER_MAX_MS`).
fn jitter() -> Duration {
    Duration::from_millis(random::range(0..REKEY_TIMEOUT_JITTER_MAX_MS))
}

/// Основной цикл: до команды закрытия или фатальной ошибки сокета.
pub(super) async fn run(handles: Handles) {
    let Handles {
        socket,
        static_keys,
        reserved,
        mut obfs,
        keepalive,
        mut session,
        handshake_millis,
        mut outbound_rx,
        inbound_tx,
        mut shutdown_rx,
    } = handles;

    let mut recv_buf = vec![0u8; RECV_BUFFER_LEN];
    let mut send_buf = Vec::with_capacity(RECV_BUFFER_LEN);
    let mut rekey: Option<RekeyAttempt> = None;
    let mut last_sent_data = Instant::now();
    let timer =
        tokio::time::sleep_until(wake_at(&session, &rekey, keepalive, last_sent_data).into());
    tokio::pin!(timer);

    loop {
        tokio::select! {
            biased;

            _ = &mut shutdown_rx => {
                tracing::debug!("направление WireGuard закрывается по команде");
                break;
            }

            outgoing = outbound_rx.recv() => {
                let Some(packet) = outgoing else { break };
                let padding = data_padding(&mut obfs, packet.len());
                if let Err(error) = session.seal_packet(reserved, &packet, padding, &mut send_buf) {
                    tracing::warn!(%error, "сеанс WireGuard не может больше шифровать — направление закрывается");
                    break;
                }
                if let Some(o) = &obfs {
                    o.wrap_transport(&mut send_buf);
                }
                if socket.send(&send_buf).await.is_err() {
                    break;
                }
                last_sent_data = Instant::now();
            }

            incoming = socket.recv(&mut recv_buf) => {
                let Ok(len) = incoming else { break };
                match handle_datagram(
                    &mut recv_buf[..len],
                    &mut obfs,
                    &static_keys,
                    &mut session,
                    &mut rekey,
                    &inbound_tx,
                ).await {
                    Handled::Continue => {}
                    Handled::Rekeyed(millis) => handshake_millis.store(millis, Ordering::Relaxed),
                    Handled::Stop => break,
                }
            }

            () = &mut timer => {
                if session.is_expired() {
                    tracing::warn!(age = ?session.age(), "сеанс WireGuard истёк без обновления рукопожатия");
                    break;
                }
                advance_rekey(&socket, &static_keys, reserved, &obfs, &session, &mut rekey).await;
                if let Some(interval) = keepalive
                    && last_sent_data.elapsed() >= interval
                {
                    send_keepalive(&socket, reserved, &mut obfs, &mut session, &mut send_buf, &mut last_sent_data).await;
                }
                timer.as_mut().reset(wake_at(&session, &rekey, keepalive, last_sent_data).into());
            }
        }
    }
}

/// Ближайший момент, когда таймеру есть что делать.
fn wake_at(
    session: &Session,
    rekey: &Option<RekeyAttempt>,
    keepalive: Option<Duration>,
    last_sent_data: Instant,
) -> Instant {
    let mut due = session.expires_at();
    due = due.min(
        rekey
            .as_ref()
            .map_or_else(|| session.rekey_at(), RekeyAttempt::next_due),
    );
    if let Some(interval) = keepalive {
        due = due.min(last_sent_data + interval);
    }
    due.max(Instant::now() + MIN_WAKE)
}

/// Чем кончился разбор входящей датаграммы.
enum Handled {
    Continue,
    /// Рукопожатие обновлено за столько миллисекунд.
    Rekeyed(u32),
    /// Получатель `recv()` ушёл, задачу пора остановить.
    Stop,
}

/// Разбирает входящую датаграмму; постороннее отбрасывается молча.
async fn handle_datagram(
    datagram: &mut [u8],
    obfs: &mut Option<Obfuscation>,
    static_keys: &StaticKeys,
    session: &mut Session,
    rekey: &mut Option<RekeyAttempt>,
    inbound_tx: &mpsc::Sender<Bytes>,
) -> Handled {
    let (incoming, start, end) = classify_incoming(datagram, obfs);
    match incoming {
        Incoming::Transport => {
            // AWG: вернуть стандартный заголовок типа 4 (он вне AEAD) для разбора.
            if obfs.is_some() {
                datagram[start..start + 4].copy_from_slice(&[MESSAGE_TRANSPORT_DATA, 0, 0, 0]);
            }
            let Ok(plaintext) = session.open_packet(&mut datagram[start..end]) else {
                return Handled::Continue;
            };
            if let Some(o) = obfs {
                o.observe_received(start, plaintext.len());
            }
            // `None` - keepalive сервера (в том числе с добавкой нулей) или не IP.
            let Some(packet) = transport::inner_packet(plaintext) else {
                return Handled::Continue;
            };
            match inbound_tx.send(Bytes::copy_from_slice(packet)).await {
                Ok(()) => Handled::Continue,
                Err(_) => Handled::Stop,
            }
        }
        Incoming::Response => accept_rekey(&datagram[start..end], static_keys, session, rekey)
            .map_or(Handled::Continue, Handled::Rekeyed),
        Incoming::Cookie => {
            tracing::debug!("сервер прислал cookie-ответ: cookie-протокол не реализован");
            Handled::Continue
        }
        Incoming::Other => Handled::Continue,
    }
}

/// Принимает ответ на обновление рукопожатия; `Some` - время оборота, мс.
fn accept_rekey(
    message: &[u8],
    static_keys: &StaticKeys,
    session: &mut Session,
    rekey: &mut Option<RekeyAttempt>,
) -> Option<u32> {
    let attempt = rekey.take()?;
    match response::parse(message) {
        Ok(fields) if fields.receiver_index == attempt.pending.local_index() => {
            match consume_response(static_keys, attempt.pending, message) {
                Ok(keys) => {
                    *session = Session::new(keys);
                    return Some(millis_since(attempt.last_sent_at));
                }
                Err(error) => {
                    tracing::debug!(%error, "ответ на обновление рукопожатия не принят");
                }
            }
        }
        _ => *rekey = Some(attempt),
    }
    None
}

/// Отправляет инициацию; `Some` - она ушла.
async fn initiate(
    socket: &UdpSocket,
    static_keys: &StaticKeys,
    reserved: [u8; 3],
    obfs: &Option<Obfuscation>,
) -> Option<PendingHandshake> {
    let (message, pending) = create_initiation(static_keys, init_header(reserved, obfs));
    send_initiation_datagram(socket, &message, obfs)
        .await
        .ok()
        .map(|()| pending)
}

/// Шаг обновления рукопожатия: начать, повторить или сдаться до следующего круга.
async fn advance_rekey(
    socket: &UdpSocket,
    static_keys: &StaticKeys,
    reserved: [u8; 3],
    obfs: &Option<Obfuscation>,
    session: &Session,
    rekey: &mut Option<RekeyAttempt>,
) {
    let Some(attempt) = rekey.take() else {
        if session.needs_rekey()
            && let Some(pending) = initiate(socket, static_keys, reserved, obfs).await
        {
            let now = Instant::now();
            *rekey = Some(RekeyAttempt {
                pending,
                first_sent_at: now,
                last_sent_at: now,
                retry_after: REKEY_TIMEOUT + jitter(),
            });
        }
        return;
    };

    let now = Instant::now();
    if now.duration_since(attempt.first_sent_at) > REKEY_ATTEMPT_TIME {
        tracing::warn!(
            "не удалось обновить рукопожатие WireGuard за {REKEY_ATTEMPT_TIME:?}, сеанс работает на старых ключах"
        );
        return;
    }
    if now.duration_since(attempt.last_sent_at) < attempt.retry_after {
        *rekey = Some(attempt);
        return;
    }
    *rekey = Some(match initiate(socket, static_keys, reserved, obfs).await {
        Some(pending) => RekeyAttempt {
            pending,
            first_sent_at: attempt.first_sent_at,
            last_sent_at: now,
            retry_after: REKEY_TIMEOUT + jitter(),
        },
        None => attempt,
    });
}

/// Пустой пакет: напоминает NAT о себе, когда приложения молчат.
async fn send_keepalive(
    socket: &UdpSocket,
    reserved: [u8; 3],
    obfs: &mut Option<Obfuscation>,
    session: &mut Session,
    buf: &mut Vec<u8>,
    last_sent_data: &mut Instant,
) {
    let padding = data_padding(obfs, 0);
    if session.seal_packet(reserved, &[], padding, buf).is_err() {
        return;
    }
    if let Some(o) = obfs {
        o.wrap_transport(buf);
    }
    if socket.send(buf).await.is_ok() {
        *last_sent_data = Instant::now();
    }
}
