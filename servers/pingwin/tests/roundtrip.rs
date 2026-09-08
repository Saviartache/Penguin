//! Проверка от края до края: настоящий клиент, настоящий сервер, настоящие
//! сокеты.
//!
//! Разбор кадров и ключевое расписание проверены своими тестами в
//! `protocols/pingwin`. Здесь проверяется то, чего они увидеть не могут:
//! что клиент и сервер, собранные порознь, договариваются друг с другом и
//! действительно переносят байты — включая случай, когда клиент чужой и
//! соединение обязано уйти прикрытию.

// Проверка падает там, где сервер повёл себя не по протоколу: это не
// «ошибка, которую надо обработать», а провалившийся тест.
#![allow(clippy::expect_used)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_core::id::OutboundId;
use penguin_pingwin::config::PingwinConfig;
use penguin_pingwin::outbound::PingwinOutbound;
use penguin_pingwin_server::{Server, ServerConfig, User};
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Выход наружу без тоннеля — то, чем в настоящем клиенте служит движок.
struct Direct;

#[async_trait]
impl Dialer for Direct {
    async fn dial_tcp(&self, addr: SocketAddr) -> Result<TcpStream, ProtocolError> {
        TcpStream::connect(addr)
            .await
            .map_err(|err| ProtocolError::Connect(err.to_string()))
    }

    async fn bind_udp(&self, local: SocketAddr) -> Result<UdpSocket, ProtocolError> {
        UdpSocket::bind(local)
            .await
            .map_err(|err| ProtocolError::Connect(err.to_string()))
    }

    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ProtocolError> {
        Ok(tokio::net::lookup_host((host, 0))
            .await
            .map_err(|err| ProtocolError::Connect(err.to_string()))?
            .map(|addr| addr.ip())
            .collect())
    }
}

/// Поднимает сервер Pingwin на свободном порту.
///
/// Возвращает адрес, открытый ключ и сторожа: пока он жив, сервер работает.
async fn start_server(
    cover: Option<SocketAddr>,
) -> (SocketAddr, String, tokio::task::JoinHandle<()>) {
    // Порт выбирает система: два теста, запущенные разом, не должны драться
    // за одно и то же число.
    let probe = TcpListener::bind(("127.0.0.1", 0)).await.expect("порт");
    let addr = probe.local_addr().expect("адрес");
    drop(probe);

    let keys = penguin_pingwin::StaticKeyPair::generate();
    let config = ServerConfig {
        listen: addr.to_string(),
        key: penguin_core::base64::encode(&keys.secret_bytes()),
        fallback: cover.map(|addr| addr.to_string()).unwrap_or_default(),
        users: vec![User {
            name: "petya".to_owned(),
            password: "secret".to_owned(),
        }],
    };
    let public = penguin_core::base64::encode(&keys.public);

    let server = Arc::new(Server::new(config).expect("сервер собирается"));
    let running = tokio::spawn(async move {
        let _ = server.run(std::future::pending::<()>()).await;
    });

    // Даём слушателю встать: без этого первое же соединение попадёт в
    // закрытый порт, и тест упадёт не на том, что проверяет.
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    (addr, public, running)
}

/// Собирает направление клиента.
fn client(server: SocketAddr, key: &str, zero_rtt: bool) -> PingwinOutbound {
    let config = PingwinConfig {
        server: server.to_string(),
        key: key.to_owned(),
        password: "secret".to_owned(),
        zero_rtt,
        ..PingwinConfig::default()
    };
    PingwinOutbound::new(OutboundId::new("test"), config, Arc::new(Direct))
        .expect("направление собирается")
}

/// Поднимает сервер, который отвечает тем же, что ему прислали.
async fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("порт");
    let addr = listener.local_addr().expect("адрес");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                while let Ok(read) = socket.read(&mut buffer).await {
                    if read == 0 || socket.write_all(&buffer[..read]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// Поднимает сервер датаграмм, отвечающий тем же, что ему прислали.
async fn start_udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await.expect("порт");
    let addr = socket.local_addr().expect("адрес");
    tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
            if socket.send_to(&buffer[..read], from).await.is_err() {
                return;
            }
        }
    });
    addr
}

#[tokio::test]
async fn a_stream_carries_bytes_both_ways() {
    let echo = start_echo().await;
    let (server, key, _running) = start_server(None).await;
    let client = client(server, &key, true);

    let mut stream = client
        .connect_tcp(&SocketAddress::ip(echo.ip(), echo.port()))
        .await
        .expect("поток открылся");

    let hello = "привет".as_bytes();
    stream.write_all(hello).await.expect("записалось");
    let mut answer = vec![0u8; hello.len()];
    stream.read_exact(&mut answer).await.expect("прочиталось");
    assert_eq!(answer, hello);

    client.close().await.expect("закрылось");
}

#[tokio::test]
async fn the_second_stream_reuses_the_same_session() {
    // Ради этого мультиплексор и заведён: рукопожатие платится один раз, а
    // вкладок в браузере сотня.
    let echo = start_echo().await;
    let (server, key, _running) = start_server(None).await;
    let client = client(server, &key, true);
    let target = SocketAddress::ip(echo.ip(), echo.port());

    let mut first = client.connect_tcp(&target).await.expect("первый поток");
    let mut second = client.connect_tcp(&target).await.expect("второй поток");

    first.write_all(b"one").await.expect("записалось");
    second.write_all(b"two").await.expect("записалось");

    let mut one = [0u8; 3];
    let mut two = [0u8; 3];
    first.read_exact(&mut one).await.expect("прочиталось");
    second.read_exact(&mut two).await.expect("прочиталось");
    assert_eq!(&one, b"one");
    assert_eq!(&two, b"two");
}

#[tokio::test]
async fn a_stream_works_without_early_data_too() {
    // 0-RTT можно выключить: рукопожатие тогда обычное, в один оборот.
    let echo = start_echo().await;
    let (server, key, _running) = start_server(None).await;
    let client = client(server, &key, false);

    let mut stream = client
        .connect_tcp(&SocketAddress::ip(echo.ip(), echo.port()))
        .await
        .expect("поток открылся");
    stream.write_all(b"ping").await.expect("записалось");

    let mut answer = [0u8; 4];
    stream.read_exact(&mut answer).await.expect("прочиталось");
    assert_eq!(&answer, b"ping");
}

#[tokio::test]
async fn a_datagram_goes_out_and_comes_back() {
    let echo = start_udp_echo().await;
    let (server, key, _running) = start_server(None).await;
    let client = client(server, &key, true);

    let channel = client.bind_udp().await.expect("канал открылся");
    let target = SocketAddress::ip(echo.ip(), echo.port());
    channel
        .send_to(Bytes::from_static(b"query"), &target)
        .await
        .expect("ушла");

    let (payload, from) =
        tokio::time::timeout(std::time::Duration::from_secs(5), channel.recv_from())
            .await
            .expect("не дождались ответа")
            .expect("пришла");
    assert_eq!(payload, Bytes::from_static(b"query"));
    assert_eq!(from.port, echo.port());
}

#[tokio::test]
async fn an_unreachable_target_is_refused_by_name() {
    // Отказ обязан прийти отказом, а не молчанием: иначе приложение сочтёт
    // его обрывом и будет пробовать снова.
    let (server, key, _running) = start_server(None).await;
    let client = client(server, &key, true);

    // Порт, на котором заведомо никого нет: слушателя открыли и закрыли.
    let closed = TcpListener::bind(("127.0.0.1", 0)).await.expect("порт");
    let addr = closed.local_addr().expect("адрес");
    drop(closed);

    let answer = client
        .connect_tcp(&SocketAddress::ip(addr.ip(), addr.port()))
        .await;
    let Err(err) = answer else {
        panic!("поток открылся до закрытого порта");
    };
    assert!(
        matches!(err, ProtocolError::Unreachable(_)),
        "ожидали «недостижим», получили {err:?}"
    );
}

#[tokio::test]
async fn a_wrong_key_gets_the_cover_site() {
    // Устойчивость к активной проверке: тот, кто не знает ключа, видит
    // обычный сайт, а не отказ.
    let cover = start_echo().await;
    let (server, _key, _running) = start_server(Some(cover)).await;

    let mut probe = TcpStream::connect(server).await.expect("соединились");
    // Что угодно, лишь бы это была запись TLS: сервер прочитает её, не узнает
    // и отдаст прикрытию вместе с прочитанным.
    let junk = [0x16, 0x03, 0x01, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
    probe.write_all(&junk).await.expect("записалось");

    let mut echoed = [0u8; 9];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        probe.read_exact(&mut echoed),
    )
    .await
    .expect("прикрытие молчит")
    .expect("прочиталось");
    assert_eq!(echoed, junk, "прикрытию достались не те байты");
}

#[tokio::test]
async fn a_wrong_password_does_not_connect() {
    let (server, key, _running) = start_server(None).await;
    let config = PingwinConfig {
        server: server.to_string(),
        key,
        password: "другой".to_owned(),
        ..PingwinConfig::default()
    };
    let client = PingwinOutbound::new(OutboundId::new("test"), config, Arc::new(Direct))
        .expect("направление собирается");

    let target = SocketAddress::domain("example.com", 80);
    assert!(client.connect_tcp(&target).await.is_err());
}

#[tokio::test]
async fn desync_does_not_break_the_handshake() {
    // Обход DPI меняет то, как посылка уходит в сеть, но не то, что в ней
    // написано: сервер обязан собрать её как обычно.
    let echo = start_echo().await;
    let (server, key, _running) = start_server(None).await;

    for strategy in ["multisplit", "disorder", "fake", "fakedsplit"] {
        let params = serde_json::json!({
            "server": server.to_string(),
            "key": key,
            "password": "secret",
            "desync": { "strategy": strategy, "ttl": 64 },
        });
        let config: PingwinConfig = serde_json::from_value(params).expect("разбирается");
        let client = PingwinOutbound::new(OutboundId::new("test"), config, Arc::new(Direct))
            .expect("направление собирается");

        let mut stream = client
            .connect_tcp(&SocketAddress::ip(echo.ip(), echo.port()))
            .await
            .unwrap_or_else(|err| panic!("{strategy}: {err}"));
        stream.write_all(b"dpi").await.expect("записалось");

        let mut answer = [0u8; 3];
        stream
            .read_exact(&mut answer)
            .await
            .unwrap_or_else(|err| panic!("{strategy}: {err}"));
        assert_eq!(&answer, b"dpi", "{strategy}");
    }
}
