//! Мост целиком на живых стеках: соединение, открытое исходящим стеком, принимается входящим.
//!
//! ```text
//!   outgoing::spawn ──пакеты──► [труба] ──пакеты──► stack::spawn
//!        connect()                                     accept()
//! ```

#![allow(clippy::expect_used)]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::BytesMut;
use penguin_netstack::config::StackConfig;
use penguin_netstack::outgoing;
use penguin_tun::TunDevice;
use penguin_tun::error::{TunError, TunResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

/// Один конец трубы между двумя стеками.
struct Pipe {
    outbox: mpsc::UnboundedSender<BytesMut>,
    inbox: Mutex<mpsc::UnboundedReceiver<BytesMut>>,
    mtu: u16,
    /// Теряется каждый такой пакет; 0 — без потерь.
    lose_every: u64,
    sent: std::sync::atomic::AtomicU64,
}

/// Труба: то, что один конец отправил, другой получает.
fn pipe(mtu: u16) -> (Pipe, Pipe) {
    lossy_pipe(mtu, 0)
}

/// Труба, теряющая каждый `lose_every`-й пакет в обе стороны.
fn lossy_pipe(mtu: u16, lose_every: u64) -> (Pipe, Pipe) {
    let (left_tx, left_rx) = mpsc::unbounded_channel();
    let (right_tx, right_rx) = mpsc::unbounded_channel();
    let end = |outbox, inbox| Pipe {
        outbox,
        inbox: Mutex::new(inbox),
        mtu,
        lose_every,
        sent: std::sync::atomic::AtomicU64::new(0),
    };
    (end(right_tx, left_rx), end(left_tx, right_rx))
}

#[async_trait::async_trait]
impl TunDevice for Pipe {
    fn name(&self) -> &str {
        "труба"
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    async fn recv(&self) -> TunResult<BytesMut> {
        let mut inbox = self.inbox.lock().await;
        inbox.recv().await.ok_or(TunError::Closed)
    }

    fn try_recv(&self) -> Option<BytesMut> {
        self.inbox.try_lock().ok()?.try_recv().ok()
    }

    async fn send(&self, packet: &[u8]) -> TunResult<()> {
        let sent = self.sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if self.lose_every != 0 && sent.is_multiple_of(self.lose_every) {
            return Ok(());
        }
        self.outbox
            .send(BytesMut::from(packet))
            .map_err(|_| TunError::Closed)
    }

    async fn close(&self) -> TunResult<()> {
        Ok(())
    }
}

/// Настройки исходящей стороны: адрес, который «выдал сервер».
fn outgoing_config() -> StackConfig {
    StackConfig {
        ipv4: (Ipv4Addr::new(10, 7, 0, 2), 24),
        mtu: 1420,
        ..StackConfig::default()
    }
}

/// Адрес, до которого идём (за ним второй стек).
fn target() -> SocketAddr {
    "93.184.216.34:443".parse().expect("адрес")
}

/// Поднимает оба стека на общей трубе.
fn both_stacks(
    cancel: &CancellationToken,
) -> (outgoing::OutgoingHandles, penguin_netstack::StackHandles) {
    stacks_over(pipe(1420), cancel)
}

/// Поднимает оба стека на данной трубе.
fn stacks_over(
    (left, right): (Pipe, Pipe),
    cancel: &CancellationToken,
) -> (outgoing::OutgoingHandles, penguin_netstack::StackHandles) {
    let out = outgoing::spawn(Box::new(left), outgoing_config(), cancel.clone());
    let inbound = penguin_netstack::spawn(
        Box::new(right),
        StackConfig {
            mtu: 1420,
            ..StackConfig::default()
        },
        cancel.clone(),
    );
    (out, inbound)
}

#[tokio::test]
async fn a_connection_opened_outward_is_accepted_on_the_other_side() {
    let cancel = CancellationToken::new();
    let (out, mut inbound) = both_stacks(&cancel);

    let connecting = tokio::spawn(async move { out.connector.connect(target()).await });

    let accepted = tokio::time::timeout(Duration::from_secs(10), inbound.tcp.accept())
        .await
        .expect("вторая сторона не дождалась соединения")
        .expect("стек остановился");

    assert_eq!(accepted.destination, target());
    assert_eq!(
        accepted.source.ip(),
        std::net::IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2))
    );

    let connection = connecting
        .await
        .expect("задача упала")
        .expect("соединение не открылось");
    drop(connection);
    cancel.cancel();
}

#[tokio::test]
async fn data_flows_both_ways_through_the_bridge() {
    let cancel = CancellationToken::new();
    let (out, mut inbound) = both_stacks(&cancel);

    // `out` умирает вместе с задачей, поток обязан пережить это.
    let connecting = tokio::spawn(async move { out.connector.connect(target()).await });

    let mut accepted = tokio::time::timeout(Duration::from_secs(10), inbound.tcp.accept())
        .await
        .expect("вторая сторона не дождалась соединения")
        .expect("стек остановился")
        .connection;

    let mut connection = connecting
        .await
        .expect("задача упала")
        .expect("соединение не открылось");

    connection
        .write_all("привет".as_bytes())
        .await
        .expect("запись");
    connection.flush().await.expect("сброс");

    let mut got = vec![0u8; "привет".len()];
    tokio::time::timeout(Duration::from_secs(10), accepted.read_exact(&mut got))
        .await
        .expect("данные не дошли")
        .expect("чтение");
    assert_eq!(got, "привет".as_bytes());

    accepted
        .write_all("ответ".as_bytes())
        .await
        .expect("запись");
    accepted.flush().await.expect("сброс");

    let mut back = vec![0u8; "ответ".len()];
    tokio::time::timeout(Duration::from_secs(10), connection.read_exact(&mut back))
        .await
        .expect("ответ не дошёл")
        .expect("чтение");
    assert_eq!(back, "ответ".as_bytes());

    cancel.cancel();
}

#[tokio::test]
async fn a_datagram_goes_out_and_the_answer_comes_back_to_its_owner() {
    let cancel = CancellationToken::new();
    let (mut out, mut inbound) = both_stacks(&cancel);

    let app: SocketAddr = "10.0.0.9:51000".parse().expect("адрес");
    let dns: SocketAddr = "8.8.8.8:53".parse().expect("адрес");

    out.udp_send
        .send(penguin_netstack::Datagram {
            source: app,
            destination: dns,
            payload: bytes::Bytes::from_static(b"query"),
        })
        .await
        .expect("очередь жива");

    let seen = tokio::time::timeout(Duration::from_secs(10), inbound.udp_incoming.recv())
        .await
        .expect("датаграмма не дошла")
        .expect("стек остановился");
    assert_eq!(seen.destination, dns);
    assert_eq!(&seen.payload[..], b"query");

    inbound
        .udp_outgoing
        .send(penguin_netstack::Datagram {
            source: seen.source,
            destination: seen.destination,
            payload: bytes::Bytes::from_static(b"answer"),
        })
        .await
        .expect("очередь жива");

    let back = tokio::time::timeout(Duration::from_secs(10), out.udp_recv.recv())
        .await
        .expect("ответ не дошёл")
        .expect("стек остановился");

    assert_eq!(back.source, app);
    assert_eq!(back.destination, dns);
    assert_eq!(&back.payload[..], b"answer");

    cancel.cancel();
}

#[tokio::test]
async fn nobody_answers_and_the_request_ends_with_silence_not_a_hang() {
    let cancel = CancellationToken::new();
    let (left, right) = pipe(1420);
    // Второй конец держим, но не читаем.
    let _dangling = right;

    let out = outgoing::spawn(Box::new(left), outgoing_config(), cancel.clone());

    let error = tokio::time::timeout(
        outgoing::run::CONNECT_TIMEOUT + Duration::from_secs(5),
        out.connector.connect(target()),
    )
    .await
    .expect("запрос повис вместо того, чтобы кончиться")
    .expect_err("соединения быть не могло");

    assert!(
        matches!(error, outgoing::ConnectError::TimedOut(_)),
        "молчание показано как {error}"
    );
    cancel.cancel();
}

#[tokio::test]
async fn a_stopped_stack_answers_instead_of_leaving_the_request_hanging() {
    let cancel = CancellationToken::new();
    let (left, _right) = pipe(1420);
    let out = outgoing::spawn(Box::new(left), outgoing_config(), cancel.clone());

    cancel.cancel();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let error = tokio::time::timeout(Duration::from_secs(5), out.connector.connect(target()))
        .await
        .expect("запрос повис")
        .expect_err("стек остановлен");
    assert_eq!(error, outgoing::ConnectError::Stopped);
}

#[tokio::test]
async fn a_v6_destination_without_a_v6_address_fails_at_once() {
    let cancel = CancellationToken::new();
    let (left, _right) = pipe(1420);
    let out = outgoing::spawn(Box::new(left), outgoing_config(), cancel.clone());

    let destination: SocketAddr = "[2001:db8::1]:443".parse().expect("адрес");
    let error = tokio::time::timeout(Duration::from_secs(2), out.connector.connect(destination))
        .await
        .expect("ответ должен быть немедленным")
        .expect_err("адреса нет");

    assert_eq!(error, outgoing::ConnectError::NoAddress(destination));
    cancel.cancel();
}

/// Узнаваемые байты: перестановка или дыра в потоке видна по содержимому.
fn pattern(stream: usize, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251 + stream) as u8).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_downloads_survive_packet_loss_intact() {
    const STREAMS: usize = 6;
    const SIZE: usize = 4 * 1024 * 1024;

    let cancel = CancellationToken::new();
    let (out, mut inbound) = stacks_over(lossy_pipe(1420, 97), &cancel);

    let mut readers = Vec::new();
    for stream in 0..STREAMS {
        let connector = out.connector.clone();
        let destination = SocketAddr::new(target().ip(), 1000 + stream as u16);
        readers.push(tokio::spawn(async move {
            let mut connection = connector.connect(destination).await.expect("соединение");
            let mut got = Vec::with_capacity(SIZE);
            // До конца потока: без переданного `FIN` чтение не кончится.
            connection.read_to_end(&mut got).await.expect("чтение");
            got
        }));
    }

    let mut writers = Vec::new();
    for _ in 0..STREAMS {
        let accepted = tokio::time::timeout(Duration::from_secs(10), inbound.tcp.accept())
            .await
            .expect("соединение не принято")
            .expect("стек остановился");
        let stream = usize::from(accepted.destination.port() - 1000);
        let mut connection = accepted.connection;
        writers.push(tokio::spawn(async move {
            connection
                .write_all(&pattern(stream, SIZE))
                .await
                .expect("запись");
            connection.shutdown().await.expect("закрытие");
            // Держим соединение, пока стек не отдаст хвост.
            let mut rest = Vec::new();
            let _ = connection.read_to_end(&mut rest).await;
        }));
    }

    // Меньше периода keep-alive (30 с): потерянное обновление окна без проб ждало бы его.
    for (stream, reader) in readers.into_iter().enumerate() {
        let got = tokio::time::timeout(Duration::from_secs(15), reader)
            .await
            .expect("загрузка встала")
            .expect("задача упала");
        assert_eq!(got.len(), SIZE, "поток {stream} оборван");
        assert!(got == pattern(stream, SIZE), "поток {stream} испорчен");
    }
    drop(writers);
    cancel.cancel();
}
