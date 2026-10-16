//! Проверка от края до края: настоящий клиент, настоящий сервер, настоящие
//! сокеты, QUIC и HTTP/3 на петле.
//!
//! Ключи, токен и датаграммы проверены своими тестами в `protocols/pingwin`.
//! Здесь — то, чего они увидеть не могут: что клиент и сервер, собранные
//! порознь, опознают друг друга, переносят байты и что чужой видит сайт.

// Проверка падает там, где сервер повёл себя не по протоколу.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::{Address, SocketAddress};
use penguin_core::id::OutboundId;
use penguin_pingwin::config::PingwinConfig;
use penguin_pingwin::outbound::PingwinOutbound;
use penguin_pingwin_server::{Server, ServerConfig, User};
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::ProtocolFactory;
use penguin_proto::outbound::Outbound;
use penguin_transport::h3::{self, Request};
use penguin_transport::quic;
use penguin_transport::tls::{ALPN_H3, TlsConfig};
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

    async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, ProtocolError> {
        Ok(vec![IpAddr::from([127, 0, 0, 1])])
    }
}

/// Файлы `tests/fixtures`: корень `ca.crt` и лист `localhost.crt` от него.
///
/// Лист живёт 825 дней (до 18.01.2029) — дольше macOS не принимает даже от
/// своего корня. Истёк — выпустить новый тем же `openssl x509 -req` от
/// нового корня: `serverAuth`, `DNS:localhost`, `-days 825`.
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Каталог прикрытия с одной страницей.
fn cover_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pingwin-cover-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("каталог");
    std::fs::write(dir.join("index.html"), "<h1>cover</h1>").expect("страница");
    dir
}

/// Поднимает сервер на свободном порту; возвращает адрес и открытый ключ.
async fn start_server() -> (SocketAddr, String) {
    let probe = UdpSocket::bind(("127.0.0.1", 0)).await.expect("порт");
    let addr = probe.local_addr().expect("адрес");
    drop(probe);

    let keys = penguin_pingwin::StaticKeyPair::generate();
    let config = ServerConfig {
        listen: addr.to_string(),
        key: penguin_core::base64::encode(&keys.secret_bytes()),
        cert: fixture("localhost.crt"),
        cert_key: fixture("localhost.key"),
        cover: Some(cover_dir()),
        users: vec![User {
            name: "petya".to_owned(),
            password: "secret".to_owned(),
        }],
    };
    let server = Arc::new(Server::new(config).expect("сервер собирается"));
    tokio::spawn(async move { server.run(std::future::pending::<()>()).await });
    // Первый пакет до привязки сокета не потеряется насовсем: QUIC его
    // повторит. Пауза лишь избавляет тест от лишней секунды.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, penguin_core::base64::encode(&keys.public))
}

fn config(server: SocketAddr, key: &str, password: &str) -> PingwinConfig {
    PingwinConfig {
        server: server.to_string(),
        key: key.to_owned(),
        password: password.to_owned(),
        sni: "localhost".to_owned(),
        // Сертификат проверяется по-настоящему: свой корень вместо общего.
        ca: Some(fixture("ca.crt").display().to_string()),
    }
}

fn client(server: SocketAddr, key: &str) -> PingwinOutbound {
    PingwinOutbound::new(
        OutboundId::new("test"),
        config(server, key, "secret"),
        Arc::new(Direct),
    )
    .expect("направление собирается")
}

/// Сервер, который отвечает тем же, что ему прислали.
async fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("порт");
    let addr = listener.local_addr().expect("адрес");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = socket.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    addr
}

/// Сервер датаграмм, отвечающий тем же, что ему прислали.
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

/// Сервер, который на любой запрос выливает `bytes` байт.
async fn start_source(bytes: usize) -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("порт");
    let addr = listener.local_addr().expect("адрес");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut hello = [0u8; 8];
                let _ = socket.read(&mut hello).await;
                let chunk = vec![0x5Au8; 256 * 1024];
                let mut sent = 0;
                while sent < bytes && socket.write_all(&chunk).await.is_ok() {
                    sent += chunk.len();
                }
            });
        }
    });
    addr
}

/// Сервер, который читает и выбрасывает.
async fn start_sink() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("порт");
    let addr = listener.local_addr().expect("адрес");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 256 * 1024];
                while socket.read(&mut buffer).await.is_ok_and(|read| read > 0) {}
            });
        }
    });
    addr
}

fn target(addr: SocketAddr) -> SocketAddress {
    SocketAddress::ip(addr.ip(), addr.port())
}

#[tokio::test]
async fn a_stream_carries_bytes_both_ways() {
    let echo = start_echo().await;
    let (server, key) = start_server().await;
    let client = client(server, &key);

    let mut stream = client.connect_tcp(&target(echo)).await.expect("поток");
    let hello = "привет".as_bytes();
    stream.write_all(hello).await.expect("записалось");
    let mut answer = vec![0u8; hello.len()];
    stream.read_exact(&mut answer).await.expect("прочиталось");
    assert_eq!(answer, hello);

    // Полузакрытие доезжает до цели, и её конец — до клиента.
    stream.shutdown().await.expect("конец записи");
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.expect("дочиталось");
    assert!(rest.is_empty());

    client.close().await.expect("закрылось");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_streams_at_once_share_one_connection() {
    let echo = start_echo().await;
    let (server, key) = start_server().await;
    let client = Arc::new(client(server, &key));

    let mut tasks = Vec::new();
    for index in 0u8..8 {
        let client = Arc::clone(&client);
        tasks.push(tokio::spawn(async move {
            let mut stream = client.connect_tcp(&target(echo)).await.expect("поток");
            let payload = vec![index; 200_000 + usize::from(index) * 3000];
            for _ in 0..4 {
                stream.write_all(&payload).await.expect("записалось");
                let mut answer = vec![0u8; payload.len()];
                stream.read_exact(&mut answer).await.expect("прочиталось");
                assert_eq!(answer, payload, "поток {index} получил чужие байты");
            }
        }));
    }
    for task in tasks {
        task.await.expect("поток отработал без паники");
    }
}

/// Скорость одного потока на петле: печатается, а не проверяется порогом.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn how_fast_one_stream_goes_on_loopback() {
    const BYTES: usize = 64 * 1024 * 1024;
    let sink = start_sink().await;
    let (server, key) = start_server().await;
    let client = client(server, &key);

    let mut stream = client.connect_tcp(&target(sink)).await.expect("поток");
    let chunk = vec![0x5Au8; 256 * 1024];
    let started = std::time::Instant::now();
    let mut sent = 0;
    while sent < BYTES {
        stream.write_all(&chunk).await.expect("записалось");
        sent += chunk.len();
    }
    stream.flush().await.expect("сбросилось");
    let speed = sent as f64 / started.elapsed().as_secs_f64() / 1_000_000.0;
    println!("    отдача на петле: {speed:.0} МБ/с");
    assert!(
        speed > 1.0,
        "меньше мегабайта в секунду на петле — это поломка"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn how_fast_one_stream_downloads_on_loopback() {
    const BYTES: usize = 64 * 1024 * 1024;
    let source = start_source(BYTES).await;
    let (server, key) = start_server().await;
    let client = client(server, &key);

    let mut stream = client.connect_tcp(&target(source)).await.expect("поток");
    stream.write_all(b"go").await.expect("записалось");
    let started = std::time::Instant::now();
    let mut buffer = vec![0u8; 256 * 1024];
    let mut got = 0;
    while got < BYTES {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => got += read,
        }
    }
    let speed = got as f64 / started.elapsed().as_secs_f64() / 1_000_000.0;
    println!(
        "    скачивание на петле: {speed:.0} МБ/с ({} МБ)",
        got / 1_000_000
    );
    assert_eq!(got, BYTES);
}

#[tokio::test]
async fn the_latency_comes_from_quic() {
    let (server, key) = start_server().await;
    let client = client(server, &key);
    assert!(client.rtt().await.is_none(), "соединения ещё нет");

    client.warm_up().await.expect("подключились");
    let rtt = client.rtt().await.expect("QUIC знает оборот");
    assert!(
        rtt.millis < 1000,
        "петля не может отвечать секунду: {rtt:?}"
    );
}

#[tokio::test]
async fn a_datagram_goes_out_and_comes_back() {
    let echo = start_udp_echo().await;
    let (server, key) = start_server().await;
    let client = client(server, &key);

    let channel = client.bind_udp().await.expect("канал открылся");
    channel
        .send_to(Bytes::from_static(b"query"), &target(echo))
        .await
        .expect("ушла");
    let (payload, from) = tokio::time::timeout(Duration::from_secs(5), channel.recv_from())
        .await
        .expect("не дождались ответа")
        .expect("пришла");
    assert_eq!(payload, Bytes::from_static(b"query"));
    assert_eq!(from, target(echo));
    channel.close().await.expect("закрылся");
}

#[tokio::test]
async fn an_unreachable_target_says_so_on_the_first_read() {
    let (server, key) = start_server().await;
    let client = client(server, &key);

    let closed = TcpListener::bind(("127.0.0.1", 0)).await.expect("порт");
    let addr = closed.local_addr().expect("адрес");
    drop(closed);

    let mut stream = client
        .connect_tcp(&target(addr))
        .await
        .expect("поток открывается, не дожидаясь ответа");
    let mut answer = [0u8; 64];
    let err = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut answer))
        .await
        .expect("отказ не пришёл за десять секунд")
        .expect_err("цели нет, чтения быть не может");
    let text = err.to_string();
    assert!(text.contains(&addr.to_string()), "цель потерялась: {text}");
    // Повторное чтение не паникует и говорит то же.
    assert!(stream.read(&mut answer).await.is_err());
}

#[tokio::test]
async fn a_wrong_password_is_an_auth_rejection() {
    let (server, key) = start_server().await;
    let client = PingwinOutbound::new(
        OutboundId::new("test"),
        config(server, &key, "другой"),
        Arc::new(Direct),
    )
    .expect("направление собирается");
    let err = ProtocolError::from(client.warm_up().await.expect_err("пускать нельзя"));
    assert!(matches!(err, ProtocolError::AuthRejected), "{err}");
}

#[tokio::test]
async fn a_server_with_another_key_is_an_auth_rejection() {
    let (server, _key) = start_server().await;
    let other = penguin_core::base64::encode(&penguin_pingwin::StaticKeyPair::generate().public);
    let client = client(server, &other);
    let err = ProtocolError::from(client.warm_up().await.expect_err("сервер не тот"));
    assert!(matches!(err, ProtocolError::AuthRejected), "{err}");
}

#[tokio::test]
async fn a_certificate_for_another_name_does_not_connect() {
    let (server, key) = start_server().await;
    let client = PingwinOutbound::new(
        OutboundId::new("test"),
        PingwinConfig {
            sni: "other.example.com".to_owned(),
            ..config(server, &key, "secret")
        },
        Arc::new(Direct),
    )
    .expect("направление собирается");
    assert!(client.warm_up().await.is_err());
}

/// Обычный клиент HTTP/3 на соединении без опознания.
async fn probe(server: SocketAddr) -> (quic::QuicLink, h3::Connection) {
    let tls = TlsConfig {
        ca: Some(fixture("ca.crt").display().to_string()),
        ..TlsConfig::default()
    };
    let link = quic::connect(
        &Direct,
        &Address::Ip(server.ip()),
        server.port(),
        "localhost",
        &tls,
        &[ALPN_H3],
    )
    .await
    .expect("QUIC");
    let h3 = h3::Connection::new(link.connection.clone(), h3::Options::default())
        .await
        .expect("HTTP/3");
    (link, h3)
}

#[tokio::test]
async fn a_stranger_sees_a_static_site() {
    let (server, _key) = start_server().await;
    let (_link, h3) = probe(server).await;

    let mut page = h3
        .send_request(&Request::new("GET", "localhost", "/"))
        .await
        .expect("запрос");
    page.finish().expect("конец");
    assert_eq!(page.response().await.expect("ответ").status(), 200);
    let mut body = String::new();
    page.read_to_string(&mut body).await.expect("тело");
    assert_eq!(body, "<h1>cover</h1>");

    // Чужое опознание неотличимо от его отсутствия.
    let mut forged = h3
        .send_request(
            &Request::new("GET", "localhost", "/").header("authorization", "Pingwin AAAA"),
        )
        .await
        .expect("запрос");
    forged.finish().expect("конец");
    assert_eq!(forged.response().await.expect("ответ").status(), 200);

    for (method, path, status) in [
        ("GET", "/nope", 404),
        ("GET", "/../Cargo.toml", 404),
        ("POST", "/", 405),
    ] {
        let mut stream = h3
            .send_request(&Request::new(method, "localhost", path))
            .await
            .expect("запрос");
        stream.finish().expect("конец");
        assert_eq!(
            stream.response().await.expect("ответ").status(),
            status,
            "{method} {path}"
        );
    }

    // CONNECT без опознания — тоже сайт, а не прокси.
    let echo = start_echo().await;
    let mut connect = h3
        .send_request(&Request::connect(echo.to_string()))
        .await
        .expect("запрос");
    assert_eq!(connect.response().await.expect("ответ").status(), 405);
}

#[tokio::test]
async fn a_server_that_does_not_answer_is_reported_at_connect_time() {
    // Направление поднимает соединение при подключении профиля: иначе окно
    // писало бы «подключено», ни разу не сходив к серверу.
    let closed = UdpSocket::bind(("127.0.0.1", 0)).await.expect("порт");
    let addr = closed.local_addr().expect("адрес");
    drop(closed);

    let params = serde_json::json!({
        "server": addr.to_string(),
        "key": penguin_core::base64::encode(&[7u8; 32]),
        "password": "secret",
        "sni": "localhost",
    });
    let built = penguin_pingwin::PingwinFactory::new()
        .build(
            penguin_proto::factory::BuildContext {
                id: OutboundId::new("test"),
                dialer: Arc::new(Direct),
            },
            &params,
        )
        .await;
    assert!(built.is_err(), "направление собралось до мёртвого сервера");
}
