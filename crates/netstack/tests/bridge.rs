//! Мост целиком: соединение, открытое исходящим стеком, принимается входящим.
//!
//! Проверка на живых стеках, а не на записанных байтах. Между двумя стеками
//! стоит труба из двух очередей — тот же шов, что в жизни занимает
//! направление уровня пакетов. Всё, что идёт по этой трубе, — настоящие
//! IP-пакеты, собранные и разобранные настоящим smoltcp.
//!
//! ```text
//!   outgoing::spawn ──пакеты──► [труба] ──пакеты──► stack::spawn
//!        connect()                                     accept()
//! ```
//!
//! Так проверяется ровно то, ради чего мост писался: у нас есть адрес
//! назначения, и соединение открывается через интерфейс, который дало
//! направление.

// Тесты вправе падать громко: `expect` здесь и есть проверка.
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
}

/// Труба: то, что один конец отправил, другой получает.
fn pipe(mtu: u16) -> (Pipe, Pipe) {
    let (left_tx, left_rx) = mpsc::unbounded_channel();
    let (right_tx, right_rx) = mpsc::unbounded_channel();
    (
        Pipe {
            outbox: right_tx,
            inbox: Mutex::new(left_rx),
            mtu,
        },
        Pipe {
            outbox: left_tx,
            inbox: Mutex::new(right_rx),
            mtu,
        },
    )
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

/// Адрес, до которого идём. Настоящего сервера за ним нет — за ним второй стек.
fn target() -> SocketAddr {
    "93.184.216.34:443".parse().expect("адрес")
}

/// Поднимает оба стека на общей трубе.
fn both_stacks(
    cancel: &CancellationToken,
) -> (outgoing::OutgoingHandles, penguin_netstack::StackHandles) {
    let (left, right) = pipe(1420);
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

    // Назначение доехало как есть: соединение открыто именно туда, куда просили.
    assert_eq!(accepted.destination, target());
    // Отправителем стоит адрес интерфейса, а не адрес приложения: на провод
    // уходит то, что дал сервер.
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

    // Заодно проверяется, что открытое соединение переживает потерю того, кто
    // его открыл: `out` уезжает в задачу и умирает вместе с ней, а поток после
    // этого обязан работать. Закрывать живые потоки из-за того, что никто
    // больше не просит новых, нельзя.
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

    // Адрес приложения на провод не попадает — по нему движок узнаёт свою
    // сессию в ответе.
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

    // Отвечаем той же стороне: для входящего стека это обычный ответ
    // приложению, а для исходящего — ответ на его запрос.
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

    // Хозяин найден по своему порту: движок получает ровно те адреса, с
    // которыми посылал.
    assert_eq!(back.source, app);
    assert_eq!(back.destination, dns);
    assert_eq!(&back.payload[..], b"answer");

    cancel.cancel();
}

#[tokio::test]
async fn nobody_answers_and_the_request_ends_with_silence_not_a_hang() {
    // Труба в никуда: пакеты уходят, ответа нет. Запрос обязан кончиться сам.
    let cancel = CancellationToken::new();
    let (left, right) = pipe(1420);
    // Второй конец держим, но не читаем: так выглядит сервер, до которого не
    // дошло.
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
    // Даём циклу закончиться.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let error = tokio::time::timeout(Duration::from_secs(5), out.connector.connect(target()))
        .await
        .expect("запрос повис")
        .expect_err("стек остановлен");
    assert_eq!(error, outgoing::ConnectError::Stopped);
}

#[tokio::test]
async fn a_v6_destination_without_a_v6_address_fails_at_once() {
    // Сервер выдал только IPv4. Уйти на адрес IPv6 через такой интерфейс
    // нельзя, и узнать об этом надо сразу, а не через пятнадцать секунд.
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
