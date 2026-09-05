//! Задача-водитель: один сокет, один сеанс, три таймера.
//!
//! Всё, что меняет ключи или счётчики, происходит здесь и только здесь —
//! `send`/`recv` лишь передают байты через каналы (`super`). Это не
//! оптимизация, а способ не заводить `Mutex` вокруг сеанса: обновление
//! рукопожатия само может прийти в любой момент, и делить состояние между
//! задачей-водителем и вызывающими значило бы решать, кто кого ждёт.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use crate::crypto::constants::{
    MESSAGE_COOKIE_REPLY, MESSAGE_RESPONSE, MESSAGE_TRANSPORT_DATA, REKEY_ATTEMPT_TIME,
    REKEY_TIMEOUT, REKEY_TIMEOUT_JITTER_MAX_MS,
};
use crate::crypto::handshake::{PendingHandshake, StaticKeys, consume_response, create_initiation};
use crate::crypto::session::Session;
use crate::error::WireguardResult;
use crate::frame::{response, transport};

/// Самый крупный пакет, который стоит принимать одним чтением сокета.
///
/// С запасом больше любого MTU из настроек: датаграмма длиннее всё равно не
/// от WireGuard, и её стоит прочитать целиком, чтобы не оставить хвост в
/// сокете, а не отбросить середину пакета.
const RECV_BUFFER_LEN: usize = 2048;

/// Всё, что нужно задаче-водителю, чтобы начать работу.
///
/// Отдельная структура вместо длинного списка аргументов `tokio::spawn` —
/// тот и так превращает сигнатуру в одну строку без переносов.
pub(super) struct Handles {
    pub socket: Arc<UdpSocket>,
    pub static_keys: Arc<StaticKeys>,
    pub reserved: [u8; 3],
    pub keepalive: Option<Duration>,
    pub session: Session,
    pub outbound_rx: mpsc::Receiver<Bytes>,
    pub inbound_tx: mpsc::Sender<Bytes>,
    pub shutdown_rx: oneshot::Receiver<()>,
}

/// Незавершённая попытка обновить рукопожатие.
struct RekeyAttempt {
    pending: PendingHandshake,
    /// Когда эта попытка (первая из серии повторов) была начата — предел
    /// для всей серии — [`REKEY_ATTEMPT_TIME`].
    first_sent_at: Instant,
    /// Когда сообщение инициации отправлялось в последний раз.
    last_sent_at: Instant,
    /// Через сколько после `last_sent_at` стоит повторить, если ответа нет.
    retry_after: Duration,
}

/// Проводит рукопожатие с нуля, повторяя инициацию, пока сервер не ответит.
///
/// Вызывается один раз при подключении — до того, как появится сеанс,
/// который стоило бы делить с задачей-водителем.
pub(super) async fn initial_handshake(
    socket: &UdpSocket,
    keys: &StaticKeys,
    reserved: [u8; 3],
) -> WireguardResult<Session> {
    let mut buf = [0u8; RECV_BUFFER_LEN];
    loop {
        let (message, pending) = create_initiation(keys, reserved);
        socket.send(&message).await?;

        let timeout = REKEY_TIMEOUT + jitter();
        let response = tokio::time::timeout(timeout, wait_for_response(socket, &mut buf)).await;
        match response {
            Ok(Ok(len)) => match consume_response(keys, pending, &buf[..len]) {
                Ok(keys_out) => return Ok(Session::new(keys_out)),
                // Не наш ответ или испорчен — начинаем инициацию заново,
                // а не пытаемся угадать, что не так с этим одним пакетом.
                Err(_) => continue,
            },
            Ok(Err(io_error)) => return Err(io_error.into()),
            Err(_elapsed) => continue,
        }
    }
}

/// Ждёт первый пакет с типом «ответ на рукопожатие», отбрасывая всё прочее
/// (cookie-ответ, случайный мусор) молча.
async fn wait_for_response(socket: &UdpSocket, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let len = socket.recv(buf).await?;
        if buf.first() == Some(&MESSAGE_RESPONSE) {
            return Ok(len);
        }
    }
}

/// Случайный сдвиг к сроку повтора, чтобы не долбить сервер ровно по
/// расписанию (см. `REKEY_TIMEOUT_JITTER_MAX_MS`).
fn jitter() -> Duration {
    Duration::from_millis(rand::random::<u64>() % REKEY_TIMEOUT_JITTER_MAX_MS)
}

/// Основной цикл направления: живёт, пока не попросят закрыться или пока
/// сокет не откажет фатально.
pub(super) async fn run(handles: Handles) {
    let Handles {
        socket,
        static_keys,
        reserved,
        keepalive,
        mut session,
        mut outbound_rx,
        inbound_tx,
        mut shutdown_rx,
    } = handles;

    let mut recv_buf = vec![0u8; RECV_BUFFER_LEN];
    let mut rekey: Option<RekeyAttempt> = None;
    let mut last_sent_data = Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            biased;

            _ = &mut shutdown_rx => {
                tracing::debug!("направление WireGuard закрывается по команде");
                break;
            }

            outgoing = outbound_rx.recv() => {
                let Some(packet) = outgoing else {
                    // `WireguardOutbound` вместе с отправителем канала ушёл —
                    // держать сокет открытым больше не для кого.
                    break;
                };
                match session.encrypt(&packet) {
                    Ok((counter, ciphertext)) => {
                        let datagram = seal_transport(&session, reserved, counter, ciphertext);
                        if socket.send(&datagram).await.is_err() {
                            break;
                        }
                        last_sent_data = Instant::now();
                    }
                    Err(error) => {
                        tracing::warn!(%error, "сеанс WireGuard не может больше шифровать — направление закрывается");
                        break;
                    }
                }
            }

            incoming = socket.recv(&mut recv_buf) => {
                let Ok(len) = incoming else { break; };
                if !handle_datagram(
                    &recv_buf[..len],
                    &static_keys,
                    &mut session,
                    &mut rekey,
                    &inbound_tx,
                ).await {
                    break;
                }
            }

            _ = ticker.tick() => {
                if session.is_expired() {
                    tracing::warn!(age = ?session.age(), "сеанс WireGuard истёк без обновления рукопожатия");
                    break;
                }

                advance_rekey(&socket, &static_keys, reserved, &mut session, &mut rekey).await;

                if let Some(interval) = keepalive
                    && last_sent_data.elapsed() >= interval
                {
                    send_keepalive(&socket, reserved, &mut session, &mut last_sent_data).await;
                }
            }
        }
    }
}

/// Разбирает один входящий датаграм и отвечает на него по типу сообщения.
///
/// Возвращает `false`, когда получатель канала к `recv()` ушёл — это
/// единственная причина остановить всю задачу отсюда: любая другая
/// неожиданность (испорченный пакет, чужой mac1, cookie-ответ) отбрасывается
/// молча и не должна ронять уже работающий тоннель.
async fn handle_datagram(
    datagram: &[u8],
    static_keys: &StaticKeys,
    session: &mut Session,
    rekey: &mut Option<RekeyAttempt>,
    inbound_tx: &mpsc::Sender<Bytes>,
) -> bool {
    match datagram.first().copied() {
        Some(MESSAGE_TRANSPORT_DATA) => {
            let Ok((header, ciphertext)) = transport::split(datagram) else {
                return true;
            };
            if header.receiver_index != session.local_index {
                return true;
            }
            let Ok(plaintext) = session.decrypt(header.counter, ciphertext) else {
                return true;
            };
            if plaintext.is_empty() {
                // Пустой открытый текст — подтверждение (keepalive) сервера,
                // а не данные приложения.
                return true;
            }
            inbound_tx.send(Bytes::from(plaintext)).await.is_ok()
        }
        Some(MESSAGE_RESPONSE) => {
            if let Some(attempt) = rekey.take() {
                match response::parse(datagram) {
                    Ok(fields) if fields.receiver_index == attempt.pending.local_index() => {
                        match consume_response(static_keys, attempt.pending, datagram) {
                            Ok(keys) => *session = Session::new(keys),
                            Err(error) => {
                                tracing::debug!(%error, "ответ на обновление рукопожатия не принят");
                            }
                        }
                    }
                    // Не наш ответ (индекс не совпал) или не разобрался —
                    // возвращаем попытку на место и ждём настоящий ответ.
                    _ => *rekey = Some(attempt),
                }
            }
            true
        }
        Some(MESSAGE_COOKIE_REPLY) => {
            tracing::debug!(
                "сервер прислал cookie-ответ: он под нагрузкой, а cookie-протокол не реализован"
            );
            true
        }
        _ => true,
    }
}

/// Продвигает состояние обновления рукопожатия на один тик таймера: либо
/// начинает новую попытку, либо повторяет незавершённую, либо сдаётся на
/// этот раз, оставляя старый сеанс работать до истечения его собственного
/// срока.
async fn advance_rekey(
    socket: &UdpSocket,
    static_keys: &StaticKeys,
    reserved: [u8; 3],
    session: &mut Session,
    rekey: &mut Option<RekeyAttempt>,
) {
    if let Some(attempt) = rekey.take() {
        let now = Instant::now();
        if now.duration_since(attempt.first_sent_at) > REKEY_ATTEMPT_TIME {
            tracing::warn!(
                "не удалось обновить рукопожатие WireGuard за {REKEY_ATTEMPT_TIME:?} — \
                 сеанс продолжает работать на старых ключах до собственного срока"
            );
            // Оставляем `*rekey = None`: следующая проверка `needs_rekey`
            // (сеанс всё ещё не обновлён) запустит новую серию попыток сама.
        } else if now.duration_since(attempt.last_sent_at) >= attempt.retry_after {
            let (message, pending) = create_initiation(static_keys, reserved);
            if socket.send(&message).await.is_ok() {
                *rekey = Some(RekeyAttempt {
                    pending,
                    first_sent_at: attempt.first_sent_at,
                    last_sent_at: now,
                    retry_after: REKEY_TIMEOUT + jitter(),
                });
            } else {
                *rekey = Some(attempt);
            }
        } else {
            *rekey = Some(attempt);
        }
        return;
    }

    if session.needs_rekey() {
        let (message, pending) = create_initiation(static_keys, reserved);
        if socket.send(&message).await.is_ok() {
            let now = Instant::now();
            *rekey = Some(RekeyAttempt {
                pending,
                first_sent_at: now,
                last_sent_at: now,
                retry_after: REKEY_TIMEOUT + jitter(),
            });
        }
    }
}

/// Шлёт пустой пакет-подтверждение — единственный способ напомнить о себе
/// шлюзу NAT, когда приложения давно молчат.
async fn send_keepalive(
    socket: &UdpSocket,
    reserved: [u8; 3],
    session: &mut Session,
    last_sent_data: &mut Instant,
) {
    let Ok((counter, ciphertext)) = session.encrypt(&[]) else {
        return;
    };
    let datagram = seal_transport(session, reserved, counter, ciphertext);
    if socket.send(&datagram).await.is_ok() {
        *last_sent_data = Instant::now();
    }
}

/// Собирает готовый датаграм пакета данных: заголовок плюс шифротекст.
fn seal_transport(
    session: &Session,
    reserved: [u8; 3],
    counter: u64,
    ciphertext: Vec<u8>,
) -> Vec<u8> {
    let header = transport::TransportHeader {
        receiver_index: session.remote_index,
        counter,
    };
    transport::build(&header, reserved, &ciphertext)
}
