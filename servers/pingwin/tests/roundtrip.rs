//! Проверка от края до края: настоящий клиент, настоящий сервер, настоящие
//! сокеты, HTTP/3 по QUIC и HTTP/2 по TCP на петле.
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
use penguin_pingwin::config::{PingwinConfig, Transport};
use penguin_pingwin::outbound::PingwinOutbound;
use penguin_pingwin_server::{Server, ServerConfig, User};
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::factory::ProtocolFactory;
use penguin_proto::outbound::Outbound;
use penguin_transport::h3::{self, Request};
use penguin_transport::quic;
use penguin_transport::tls::{ALPN_H2, ALPN_H3, TlsClient, TlsConfig};
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
    // Сервер слушает UDP и TCP на одном порту: нужен свободный в обоих.
    let addr = loop {
        let probe = TcpListener::bind(("127.0.0.1", 0)).await.expect("порт");
        let addr = probe.local_addr().expect("адрес");
        if UdpSocket::bind(addr).await.is_ok() {
            break addr;
        }
    };

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
        transport: Transport::Quic,
    }
}

fn client_over(server: SocketAddr, key: &str, transport: Transport) -> PingwinOutbound {
    PingwinOutbound::new(
        OutboundId::new("test"),
        PingwinConfig {
            transport,
            ..config(server, key, "secret")
        },
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

/// Проверка по обоим переносам: `<имя>::quic` и `<имя>::tcp`.
macro_rules! both {
    ($(#[$attr:meta])* $name:ident) => {
        mod $name {
            use super::*;

            $(#[$attr])*
            async fn quic() {
                super::$name(Transport::Quic).await;
            }

            $(#[$attr])*
            async fn tcp() {
                super::$name(Transport::Tcp).await;
            }
        }
    };
}

both!(
    #[tokio::test]
    a_stream_carries_bytes_both_ways
);
async fn a_stream_carries_bytes_both_ways(transport: Transport) {
    let echo = start_echo().await;
    let (server, key) = start_server().await;
    let client = client_over(server, &key, transport);

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

both!(
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    many_streams_at_once_share_one_connection
);
async fn many_streams_at_once_share_one_connection(transport: Transport) {
    let echo = start_echo().await;
    let (server, key) = start_server().await;
    let client = Arc::new(client_over(server, &key, transport));

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

// Скорость одного потока на петле: печатается, а не проверяется порогом.
both!(
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    how_fast_one_stream_goes_on_loopback
);
async fn how_fast_one_stream_goes_on_loopback(transport: Transport) {
    const BYTES: usize = 64 * 1024 * 1024;
    let sink = start_sink().await;
    let (server, key) = start_server().await;
    let client = client_over(server, &key, transport);

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
    println!("    отдача на петле ({transport:?}): {speed:.0} МБ/с");
    assert!(
        speed > 1.0,
        "меньше мегабайта в секунду на петле — это поломка"
    );
}

both!(
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    how_fast_one_stream_downloads_on_loopback
);
async fn how_fast_one_stream_downloads_on_loopback(transport: Transport) {
    const BYTES: usize = 64 * 1024 * 1024;
    let source = start_source(BYTES).await;
    let (server, key) = start_server().await;
    let client = client_over(server, &key, transport);

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
        "    скачивание на петле ({transport:?}): {speed:.0} МБ/с ({} МБ)",
        got / 1_000_000
    );
    assert_eq!(got, BYTES);
}

both!(
    #[tokio::test]
    the_latency_is_measured
);
async fn the_latency_is_measured(transport: Transport) {
    let (server, key) = start_server().await;
    let client = client_over(server, &key, transport);
    assert!(client.rtt().await.is_none(), "соединения ещё нет");

    client.warm_up().await.expect("подключились");
    // У HTTP/2 оборот — первый пинг: он уходит сразу после рукопожатия.
    let rtt = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match client.rtt().await {
                Some(rtt) => return rtt,
                None => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("оборот не измерился");
    assert!(
        rtt.millis < 1000,
        "петля не может отвечать секунду: {rtt:?}"
    );
}

both!(
    #[tokio::test]
    a_datagram_goes_out_and_comes_back
);
async fn a_datagram_goes_out_and_comes_back(transport: Transport) {
    let echo = start_udp_echo().await;
    let (server, key) = start_server().await;
    let client = client_over(server, &key, transport);

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

both!(
    #[tokio::test]
    an_unreachable_target_says_so_on_the_first_read
);
async fn an_unreachable_target_says_so_on_the_first_read(transport: Transport) {
    let (server, key) = start_server().await;
    let client = client_over(server, &key, transport);

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

both!(
    #[tokio::test]
    a_wrong_password_is_an_auth_rejection
);
async fn a_wrong_password_is_an_auth_rejection(transport: Transport) {
    let (server, key) = start_server().await;
    let client = PingwinOutbound::new(
        OutboundId::new("test"),
        PingwinConfig {
            transport,
            ..config(server, &key, "другой")
        },
        Arc::new(Direct),
    )
    .expect("направление собирается");
    let err = ProtocolError::from(client.warm_up().await.expect_err("пускать нельзя"));
    assert!(matches!(err, ProtocolError::AuthRejected), "{err}");
}

both!(
    #[tokio::test]
    a_server_with_another_key_is_an_auth_rejection
);
async fn a_server_with_another_key_is_an_auth_rejection(transport: Transport) {
    let (server, _key) = start_server().await;
    let other = penguin_core::base64::encode(&penguin_pingwin::StaticKeyPair::generate().public);
    let client = client_over(server, &other, transport);
    let err = ProtocolError::from(client.warm_up().await.expect_err("сервер не тот"));
    assert!(matches!(err, ProtocolError::AuthRejected), "{err}");
}

both!(
    #[tokio::test]
    a_certificate_for_another_name_does_not_connect
);
async fn a_certificate_for_another_name_does_not_connect(transport: Transport) {
    let (server, key) = start_server().await;
    let client = PingwinOutbound::new(
        OutboundId::new("test"),
        PingwinConfig {
            sni: "other.example.com".to_owned(),
            transport,
            ..config(server, &key, "secret")
        },
        Arc::new(Direct),
    )
    .expect("направление собирается");
    assert!(client.warm_up().await.is_err());
}

#[tokio::test]
async fn auto_takes_quic_when_udp_passes() {
    let (server, key) = start_server().await;
    let client = client_over(server, &key, Transport::Auto);
    client.warm_up().await.expect("подключились");
    assert_eq!(client.transport().await, Some("quic"));
}

/// Выход, у которого UDP режут: как у мобильного оператора.
struct NoUdp;

#[async_trait]
impl Dialer for NoUdp {
    async fn dial_tcp(&self, addr: SocketAddr) -> Result<TcpStream, ProtocolError> {
        Direct.dial_tcp(addr).await
    }

    async fn bind_udp(&self, _local: SocketAddr) -> Result<UdpSocket, ProtocolError> {
        Err(ProtocolError::Connect("UDP режут".to_owned()))
    }

    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ProtocolError> {
        Direct.resolve(host).await
    }
}

#[tokio::test]
async fn auto_falls_back_to_tcp_when_udp_is_cut() {
    let echo = start_echo().await;
    let (server, key) = start_server().await;
    let client = PingwinOutbound::new(
        OutboundId::new("test"),
        PingwinConfig {
            transport: Transport::Auto,
            ..config(server, &key, "secret")
        },
        Arc::new(NoUdp),
    )
    .expect("направление собирается");

    let mut stream = client.connect_tcp(&target(echo)).await.expect("поток");
    assert_eq!(client.transport().await, Some("tcp"));
    stream.write_all(b"ping").await.expect("записалось");
    let mut answer = [0u8; 4];
    stream.read_exact(&mut answer).await.expect("прочиталось");
    assert_eq!(&answer, b"ping");
}

/// Клиент HTTP/1.1 (`curl --http1.1`): ответ целиком текстом.
async fn http1(server: SocketAddr, request: &str) -> String {
    let tls = TlsConfig {
        sni: Some("localhost".to_owned()),
        ca: Some(fixture("ca.crt").display().to_string()),
        ..TlsConfig::default()
    };
    let tcp = TcpStream::connect(server).await.expect("TCP");
    let mut io = TlsClient::new(&tls, &Address::Ip(server.ip()), &[b"http/1.1"])
        .expect("TLS")
        .connect(tcp)
        .await
        .expect("рукопожатие TLS");
    io.write_all(request.as_bytes()).await.expect("записалось");
    let mut answer = String::new();
    io.read_to_string(&mut answer).await.expect("прочиталось");
    answer
}

#[tokio::test]
async fn a_stranger_over_http1_sees_the_same_site() {
    let (server, _key) = start_server().await;

    let page = http1(server, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    assert!(page.starts_with("HTTP/1.1 200 OK\r\n"), "{page}");
    assert!(page.ends_with("\r\n\r\n<h1>cover</h1>"), "{page}");

    let missing = http1(server, "GET /nope HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    assert!(missing.starts_with("HTTP/1.1 404 "), "{missing}");

    let proxy = http1(server, "CONNECT 127.0.0.1:22 HTTP/1.1\r\n\r\n").await;
    assert!(proxy.starts_with("HTTP/1.1 405 "), "{proxy}");
}

/// Обычный клиент HTTP/2 по TCP без опознания.
async fn probe_tcp(server: SocketAddr) -> h2::client::SendRequest<Bytes> {
    let tls = TlsConfig {
        sni: Some("localhost".to_owned()),
        ca: Some(fixture("ca.crt").display().to_string()),
        ..TlsConfig::default()
    };
    let tcp = TcpStream::connect(server).await.expect("TCP");
    let io = TlsClient::new(&tls, &Address::Ip(server.ip()), &[ALPN_H2])
        .expect("TLS")
        .connect(tcp)
        .await
        .expect("рукопожатие TLS");
    let (send, connection) = h2::client::handshake(io).await.expect("HTTP/2");
    tokio::spawn(connection);
    send
}

async fn status_over_tcp(send: &h2::client::SendRequest<Bytes>, request: http::Request<()>) -> u16 {
    let (response, _) = send
        .clone()
        .ready()
        .await
        .expect("готов")
        .send_request(request, true)
        .expect("запрос");
    response.await.expect("ответ").status().as_u16()
}

#[tokio::test]
async fn a_stranger_over_tcp_sees_the_same_site() {
    let (server, _key) = start_server().await;
    let send = probe_tcp(server).await;

    let get = |path: &str| {
        http::Request::get(format!("https://localhost{path}"))
            .body(())
            .expect("запрос")
    };
    let (response, _) = send
        .clone()
        .ready()
        .await
        .expect("готов")
        .send_request(get("/"), true)
        .expect("запрос");
    let response = response.await.expect("ответ");
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let mut page = Vec::new();
    while let Some(chunk) = body.data().await {
        page.extend_from_slice(&chunk.expect("тело"));
    }
    assert_eq!(page, b"<h1>cover</h1>");

    let forged = http::Request::get("https://localhost/")
        .header("authorization", "Pingwin AAAA")
        .body(())
        .expect("запрос");
    assert_eq!(status_over_tcp(&send, forged).await, 200);
    assert_eq!(status_over_tcp(&send, get("/nope")).await, 404);

    // CONNECT без опознания — тоже сайт, а не прокси.
    let echo = start_echo().await;
    let connect = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(echo.to_string())
        .body(())
        .expect("запрос");
    let (response, _) = send
        .clone()
        .ready()
        .await
        .expect("готов")
        .send_request(connect, false)
        .expect("запрос");
    assert_eq!(response.await.expect("ответ").status(), 405);
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
