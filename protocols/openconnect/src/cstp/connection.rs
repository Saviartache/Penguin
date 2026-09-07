//! Направление уровня пакетов поверх тоннеля CSTP.
//!
//! Три задачи на одно соединение, объединённые вокруг общего состояния
//! `Shared` (половина записи и метки времени, приватные для этого модуля):
//!
//! ```text
//!  send()/close()  ──┐
//!                    ├─► Shared::write_frame ──► TLS ──► сеть
//!  таймер keepalive ─┘
//!
//!  сеть ──► TLS ──► ReadHalf ──► читающая задача ──► канал ──► recv()
//! ```
//!
//! `Shared` держит половину записи (`WriteHalf`) под `Mutex` и метки времени
//! последней отправки/приёма: писать туда умеют и `send()`, и таймер, и сама
//! читающая задача — ей случается отвечать на пробу DPD сервера немедленно, не
//! дожидаясь такта таймера. Чтение при этом отдельная половина, а не тот же
//! `Mutex`: чтение обычно ждёт данные с сети сколько угодно долго, и общий
//! замок на обе стороны означал бы, что кадр keepalive не уйдёт, пока сервер
//! что-то не пришлёт.
//!
//! Итог трёх задач сходится в один канал: любая из них может решить, что
//! направление больше не работает, — читающая при обрыве или кадре не по
//! формату, таймер при неотвеченной пробе DPD дольше `2 × dpd`
//! ([`super::keepalive`]). Канал несёт `Result`, а не только данные, ровно
//! затем, чтобы причину увидел [`PacketOutbound::recv`], а не только факт
//! остановки.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::id::OutboundId;
use penguin_proto::error::ProtocolError;
use penguin_proto::packet::{PacketInterface, PacketOutbound};
use penguin_proto::stream::ProxyStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use super::connect::Params;
use super::frame;
use super::keepalive::{self, Timeouts};
use crate::error::{OpenConnectError, OpenConnectResult};

/// Сколько пакетов из тоннеля можно накопить, пока `recv()` их не забирает.
///
/// Заметно больше окна TCP на обычной линии: без запаса читающая задача
/// упёрлась бы в переполненный канал и остановила бы разбор кадров ровно
/// тогда, когда сервер и так шлёт быстрее, чем нужно.
const QUEUE_LEN: usize = 512;

/// Как часто проверять таймеры keepalive/DPD.
///
/// Секунда — заметно меньше любого разумного `dpd`/`keepalive` (обычно
/// десятки секунд) и не создаёт заметной нагрузки простоем.
const TICK: Duration = Duration::from_secs(1);

/// Общее состояние соединения: половина записи и метки последней активности.
///
/// Разделяется между направлением, читающей задачей и таймером — все трое
/// пишут в сокет (данные, ответ на пробу сервера, свои keepalive/DPD) и
/// отмечают время своей стороны.
struct Shared {
    start: Instant,
    last_rx_ms: AtomicU64,
    last_tx_ms: AtomicU64,
    /// `0` — проба DPD не висит; иначе — момент, когда она была отправлена.
    last_probe_ms: AtomicU64,
    writer: Mutex<WriteHalf<Box<dyn ProxyStream>>>,
}

impl Shared {
    fn new(writer: WriteHalf<Box<dyn ProxyStream>>) -> Self {
        Self {
            start: Instant::now(),
            last_rx_ms: AtomicU64::new(0),
            last_tx_ms: AtomicU64::new(0),
            last_probe_ms: AtomicU64::new(0),
            writer: Mutex::new(writer),
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn mark_rx(&self) {
        self.last_rx_ms.store(self.now_ms(), Ordering::Relaxed);
    }

    fn mark_tx(&self) {
        self.last_tx_ms.store(self.now_ms(), Ordering::Relaxed);
    }

    fn mark_probe_sent(&self) {
        self.last_probe_ms.store(self.now_ms(), Ordering::Relaxed);
    }

    fn clear_probe(&self) {
        self.last_probe_ms.store(0, Ordering::Relaxed);
    }

    fn since_tx(&self) -> Duration {
        Duration::from_millis(
            self.now_ms()
                .saturating_sub(self.last_tx_ms.load(Ordering::Relaxed)),
        )
    }

    fn since_rx(&self) -> Duration {
        Duration::from_millis(
            self.now_ms()
                .saturating_sub(self.last_rx_ms.load(Ordering::Relaxed)),
        )
    }

    fn since_probe(&self) -> Option<Duration> {
        let probe = self.last_probe_ms.load(Ordering::Relaxed);
        (probe != 0).then(|| Duration::from_millis(self.now_ms().saturating_sub(probe)))
    }

    /// Пишет кадр целиком и сбрасывает буфер.
    async fn write_frame(&self, frame: &[u8]) -> std::io::Result<()> {
        let mut writer = self.writer.lock().await;
        writer.write_all(frame).await?;
        writer.flush().await
    }
}

/// Направление OpenConnect: тоннель CSTP, надетый на [`PacketOutbound`].
pub struct CstpConnection {
    id: OutboundId,
    interface: PacketInterface,
    shared: Arc<Shared>,
    incoming: Mutex<mpsc::Receiver<Result<Bytes, OpenConnectError>>>,
    read_task: Arc<JoinHandle<()>>,
    timer_task: JoinHandle<()>,
}

impl CstpConnection {
    /// Запускает направление поверх уже поднятого тоннеля.
    ///
    /// `tail` — байты, пришедшие вместе с ответом на `CONNECT`: сервер вправе
    /// прислать первый кадр тем же пакетом, и потерять их значило бы потерять
    /// начало каждого такого соединения.
    pub fn new(id: OutboundId, io: Box<dyn ProxyStream>, tail: Vec<u8>, tunnel: Params) -> Self {
        let (read_half, write_half) = tokio::io::split(io);
        let shared = Arc::new(Shared::new(write_half));
        let (tx, rx) = mpsc::channel(QUEUE_LEN);

        let read_task = Arc::new(tokio::spawn(read_loop(
            read_half,
            tail,
            tx.clone(),
            Arc::clone(&shared),
        )));

        let timeouts = Timeouts {
            keepalive: tunnel.keepalive,
            dpd: tunnel.dpd,
        };
        let timer_task = tokio::spawn(timer_loop(
            timeouts,
            Arc::clone(&shared),
            tx,
            Arc::clone(&read_task),
        ));

        Self {
            id,
            interface: PacketInterface {
                ipv4: tunnel.ipv4,
                ipv6: tunnel.ipv6,
                mtu: tunnel.mtu,
                dns: tunnel.dns,
            },
            shared,
            incoming: Mutex::new(rx),
            read_task,
            timer_task,
        }
    }
}

impl std::fmt::Debug for CstpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CstpConnection")
            .field("id", &self.id)
            .field("interface", &self.interface)
            .finish()
    }
}

#[async_trait]
impl PacketOutbound for CstpConnection {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn interface(&self) -> PacketInterface {
        self.interface.clone()
    }

    async fn send(&self, packet: &[u8]) -> Result<(), ProtocolError> {
        if packet.len() > usize::from(self.interface.mtu) {
            return Err(ProtocolError::InvalidConfig(format!(
                "пакет в {} байт длиннее MTU тоннеля ({})",
                packet.len(),
                self.interface.mtu
            )));
        }
        let frame = frame::encode(frame::DATA, packet)?;
        self.shared.write_frame(&frame).await?;
        self.shared.mark_tx();
        Ok(())
    }

    async fn recv(&self) -> Result<Bytes, ProtocolError> {
        let mut incoming = self.incoming.lock().await;
        match incoming.recv().await {
            Some(Ok(packet)) => Ok(packet),
            Some(Err(err)) => Err(err.into()),
            // Обе задачи закрылись, не оставив причины, — такое бывает только
            // если направление уже закрыто через `close()`.
            None => Err(ProtocolError::Disconnected(
                "направление закрыто".to_owned(),
            )),
        }
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        // BYE с меткой добровольного выхода (`cstp.c`, `0xb0`): без неё
        // сервер учёл бы уход как временный обрыв, а не как отключение
        // (`worker-vpn.c`). Отправка — попытка вежливости, а не условие
        // закрытия: не получилось — закрываем всё равно.
        let mut payload = vec![frame::DISCONN_USER_QUIT];
        payload.extend_from_slice(b"disconnected by user");
        if let Ok(frame) = frame::encode(frame::DISCONN, &payload) {
            let _ = self.shared.write_frame(&frame).await;
        }
        self.read_task.abort();
        self.timer_task.abort();
        Ok(())
    }
}

/// Читает кадры из сети и раскладывает их по смыслу.
async fn read_loop(
    mut reader: ReadHalf<Box<dyn ProxyStream>>,
    tail: Vec<u8>,
    tx: mpsc::Sender<Result<Bytes, OpenConnectError>>,
    shared: Arc<Shared>,
) {
    // Байты, пришедшие вместе с ответом на `CONNECT`, — начало потока кадров,
    // а не мусор: сервер вправе прислать первый кадр тем же пакетом.
    let mut buffered = tail;

    loop {
        let header = match read_header(&mut reader, &mut buffered).await {
            Ok(header) => header,
            Err(err) => {
                let _ = tx.send(Err(err)).await;
                return;
            }
        };
        let payload = match read_payload(&mut reader, &mut buffered, header.len).await {
            Ok(payload) => payload,
            Err(err) => {
                let _ = tx.send(Err(err)).await;
                return;
            }
        };
        shared.mark_rx();

        match header.kind {
            frame::DATA => {
                if tx.send(Ok(Bytes::from(payload))).await.is_err() {
                    // Получателя больше нет: направление закрыли снаружи.
                    return;
                }
            }
            frame::KEEPALIVE => {}
            frame::DPD_RESP => shared.clear_probe(),
            frame::DPD_OUT => {
                // Сервер и сам отвечает на нашу пробу тем же телом
                // (`worker-vpn.c`); делаем то же самое для его пробы.
                if let Ok(reply) = frame::encode(frame::DPD_RESP, &payload) {
                    let _ = shared.write_frame(&reply).await;
                }
            }
            frame::TERM_SERVER => {
                let _ = tx
                    .send(Err(OpenConnectError::disconnected(
                        "сервер разорвал сессию (AC_PKT_TERM_SERVER)",
                    )))
                    .await;
                return;
            }
            frame::DISCONN => {
                let _ = tx
                    .send(Err(OpenConnectError::disconnected("сервер закрыл сессию")))
                    .await;
                return;
            }
            other => {
                let _ = tx
                    .send(Err(OpenConnectError::frame(format!(
                        "кадр типа {other}: сжатие не поддержано, а других незнакомых \
                         типов протокол не ждёт"
                    ))))
                    .await;
                return;
            }
        }
    }
}

/// Читает заголовок кадра, используя сперва то, что уже накоплено в буфере.
async fn read_header(
    reader: &mut ReadHalf<Box<dyn ProxyStream>>,
    buffered: &mut Vec<u8>,
) -> OpenConnectResult<frame::Header> {
    fill(reader, buffered, frame::HEADER_LEN).await?;
    let header = frame::decode_header(buffered)?;
    buffered.drain(..frame::HEADER_LEN);
    Ok(header)
}

/// Читает нагрузку кадра той же длины, что назвал заголовок.
async fn read_payload(
    reader: &mut ReadHalf<Box<dyn ProxyStream>>,
    buffered: &mut Vec<u8>,
    len: usize,
) -> OpenConnectResult<Vec<u8>> {
    fill(reader, buffered, len).await?;
    Ok(buffered.drain(..len).collect())
}

/// Дочитывает буфер до нужного размера из сети.
async fn fill(
    reader: &mut ReadHalf<Box<dyn ProxyStream>>,
    buffered: &mut Vec<u8>,
    needed: usize,
) -> OpenConnectResult<()> {
    let mut chunk = [0u8; 4096];
    while buffered.len() < needed {
        let read = reader.read(&mut chunk).await.map_err(read_error)?;
        if read == 0 {
            return Err(OpenConnectError::disconnected(
                "сервер закрыл соединение посреди кадра CSTP",
            ));
        }
        buffered.extend_from_slice(&chunk[..read]);
    }
    Ok(())
}

fn read_error(err: std::io::Error) -> OpenConnectError {
    if err.kind() == std::io::ErrorKind::UnexpectedEof {
        OpenConnectError::disconnected("сервер закрыл соединение")
    } else {
        OpenConnectError::Io(err)
    }
}

/// Следит за keepalive и DPD, пока соединение живо.
async fn timer_loop(
    timeouts: Timeouts,
    shared: Arc<Shared>,
    tx: mpsc::Sender<Result<Bytes, OpenConnectError>>,
    read_task: Arc<JoinHandle<()>>,
) {
    let mut ticker = tokio::time::interval(TICK);
    loop {
        ticker.tick().await;
        let action = keepalive::decide(
            timeouts,
            shared.since_tx(),
            shared.since_rx(),
            shared.since_probe(),
        );

        match action {
            keepalive::Action::Nothing => {}
            keepalive::Action::SendKeepalive => {
                if shared
                    .write_frame(&frame::encode_empty(frame::KEEPALIVE))
                    .await
                    .is_ok()
                {
                    shared.mark_tx();
                }
            }
            keepalive::Action::SendDpdProbe => {
                if shared
                    .write_frame(&frame::encode_empty(frame::DPD_OUT))
                    .await
                    .is_ok()
                {
                    shared.mark_tx();
                    shared.mark_probe_sent();
                }
            }
            keepalive::Action::PeerIsDead => {
                let _ = tx
                    .send(Err(OpenConnectError::disconnected(
                        "сервер не отвечает дольше удвоенного срока DPD",
                    )))
                    .await;
                read_task.abort();
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::io::duplex;

    use super::*;

    fn timeouts_off() -> Params {
        Params {
            ipv4: (Ipv4Addr::new(10, 8, 0, 2), 32),
            ipv6: None,
            mtu: 1400,
            keepalive: None,
            dpd: None,
            dns: Vec::new(),
        }
    }

    fn connection(io: impl ProxyStream) -> CstpConnection {
        CstpConnection::new(
            OutboundId::new("проверка"),
            Box::new(io),
            Vec::new(),
            timeouts_off(),
        )
    }

    #[tokio::test]
    async fn a_data_frame_from_the_network_becomes_a_packet() {
        let (client, mut server) = duplex(4096);
        let connection = connection(client);

        let frame = frame::encode(frame::DATA, b"IP-packet").expect("собирается");
        server.write_all(&frame).await.expect("ушло");

        let packet = connection.recv().await.expect("пришло");
        assert_eq!(&packet[..], b"IP-packet");
    }

    #[tokio::test]
    async fn sending_wraps_the_packet_in_a_cstp_frame() {
        let (client, mut server) = duplex(4096);
        let connection = connection(client);

        connection.send("наружу".as_bytes()).await.expect("ушло");

        let mut header = [0u8; frame::HEADER_LEN];
        server.read_exact(&mut header).await.expect("заголовок");
        let parsed = frame::decode_header(&header).expect("разбирается");
        assert_eq!(parsed.kind, frame::DATA);

        let mut payload = vec![0u8; parsed.len];
        server.read_exact(&mut payload).await.expect("нагрузка");
        assert_eq!(payload, "наружу".as_bytes());
    }

    #[tokio::test]
    async fn a_packet_longer_than_the_mtu_is_refused_before_it_is_sent() {
        let (client, _server) = duplex(4096);
        let connection = connection(client);
        let huge = vec![0u8; 2000];
        let err = connection.send(&huge).await.expect_err("длиннее MTU");
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn a_dpd_probe_from_the_server_gets_an_immediate_reply() {
        let (client, mut server) = duplex(4096);
        let _connection = connection(client);

        server
            .write_all(&frame::encode_empty(frame::DPD_OUT))
            .await
            .expect("ушло");

        let mut header = [0u8; frame::HEADER_LEN];
        server.read_exact(&mut header).await.expect("ответ пришёл");
        assert_eq!(
            frame::decode_header(&header).expect("разбирается").kind,
            frame::DPD_RESP
        );
    }

    #[tokio::test]
    async fn a_server_disconnect_notice_ends_the_direction_with_a_named_reason() {
        let (client, mut server) = duplex(4096);
        let connection = connection(client);

        server
            .write_all(&frame::encode_empty(frame::TERM_SERVER))
            .await
            .expect("ушло");

        let err = connection.recv().await.expect_err("направление закрылось");
        // Сервер мог разорвать сессию временно (перезапуск, лимит); повторить
        // попытку имеет смысл, в отличие от неверного пароля.
        assert!(err.is_retryable(), "{err}");
        assert!(err.to_string().contains("сервер"), "{err}");
    }

    #[tokio::test]
    async fn dropping_the_connection_stops_delivering_more_packets_silently() {
        // Сервер закрыл TCP посреди кадра — это не «ноль пакетов», а обрыв,
        // который `supervisor` обязан увидеть и повторить попытку.
        let (client, server) = duplex(4096);
        let connection = connection(client);
        drop(server);

        let err = connection.recv().await.expect_err("обрыв");
        assert!(err.is_retryable(), "{err}");
    }

    #[tokio::test]
    async fn closing_sends_a_bye_with_the_user_quit_marker() {
        let (client, mut server) = duplex(4096);
        let connection = connection(client);
        connection.close().await.expect("закрылось");

        let mut header = [0u8; frame::HEADER_LEN];
        server.read_exact(&mut header).await.expect("BYE пришёл");
        let parsed = frame::decode_header(&header).expect("разбирается");
        assert_eq!(parsed.kind, frame::DISCONN);

        let mut payload = vec![0u8; parsed.len];
        server.read_exact(&mut payload).await.expect("нагрузка");
        assert_eq!(payload[0], frame::DISCONN_USER_QUIT);
    }

    #[tokio::test]
    async fn the_interface_reported_is_the_one_the_server_gave() {
        let (client, _server) = duplex(4096);
        let connection = connection(client);
        let interface = connection.interface();
        assert_eq!(interface.ipv4, (Ipv4Addr::new(10, 8, 0, 2), 32));
        assert_eq!(interface.mtu, 1400);
    }
}
