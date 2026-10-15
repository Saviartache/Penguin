//! Свой HTTP/3 против чужого: клиент `penguin_transport::h3`, сервер — крейт
//! `h3` 0.0.8 поверх настоящих сокетов на петле.
//!
//! Разбор кадров, QPACK и настроек проверен тестами модулей на векторах RFC.
//! Здесь — то, чего они увидеть не могут: что независимая реализация
//! понимает наш поток управления, `SETTINGS` и блоки полей, а мы — её.
//! Это не живой сервер прокси: только то, что HTTP/3 сходится.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use penguin_core::address::Address;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_transport::h3::{self, H3Error, Request};
use penguin_transport::quic;
use penguin_transport::tls::{ALPN_H3, TlsConfig};
use penguin_transport::xhttp::{XhttpClient, XhttpTarget};
use quinn::crypto::rustls::QuicServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Выход наружу без тоннеля.
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

/// Поднимает сервер `h3` на свободном порту: эхо тела и ответ, по которому
/// видно, что сервер понял в запросе.
fn start_server() -> SocketAddr {
    let certs: Vec<_> = rustls_pemfile::certs(&mut &include_bytes!("fixtures/localhost.crt")[..])
        .collect::<Result<_, _>>()
        .expect("сертификат");
    let key = rustls_pemfile::private_key(&mut &include_bytes!("fixtures/localhost.key")[..])
        .expect("ключ")
        .expect("ключ есть");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("версии")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("сертификат принят");
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls).expect("TLS для QUIC"),
    ));
    let endpoint = quinn::Endpoint::server(config, ([127, 0, 0, 1], 0).into()).expect("сокет");
    let addr = endpoint.local_addr().expect("адрес");

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(serve(incoming));
        }
    });
    addr
}

async fn serve(incoming: quinn::Incoming) {
    let connection = incoming.await.expect("рукопожатие QUIC");
    let mut connection = ::h3::server::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .build::<_, Bytes>(h3_quinn::Connection::new(connection))
        .await
        .expect("рукопожатие HTTP/3");

    while let Ok(Some(resolver)) = connection.accept().await {
        tokio::spawn(async move {
            let (request, mut stream) = resolver.resolve_request().await.expect("запрос");
            let protocol = request
                .extensions()
                .get::<::h3::ext::Protocol>()
                .map(|p| p.as_str().to_owned())
                .unwrap_or_default();
            let echo = request
                .headers()
                .get("x-echo")
                .map(|v| v.to_str().expect("текст").to_owned())
                .unwrap_or_default();
            let response = http::Response::builder()
                .status(200)
                .header("x-method", request.method().as_str())
                .header("x-scheme", request.uri().scheme_str().unwrap_or("-"))
                .header("x-path", request.uri().path())
                .header("x-authority", request.uri().authority().unwrap().as_str())
                .header("x-protocol", protocol)
                .header("x-echo", echo)
                .body(())
                .expect("ответ");
            stream.send_response(response).await.expect("ответ ушёл");

            while let Some(mut chunk) = stream.recv_data().await.expect("тело") {
                let bytes = chunk.copy_to_bytes(chunk.remaining());
                stream.send_data(bytes).await.expect("эхо");
            }
            stream.finish().await.expect("конец");
        });
    }
}

async fn client(server: SocketAddr) -> (quic::QuicLink, h3::Connection) {
    client_with(server, h3::Options { datagrams: true }).await
}

async fn client_with(server: SocketAddr, options: h3::Options) -> (quic::QuicLink, h3::Connection) {
    let tls = TlsConfig {
        // Сертификат самоподписанный; проверяется HTTP/3, а не доверие.
        insecure: true,
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
    let connection = h3::Connection::new(link.connection.clone(), options)
        .await
        .expect("HTTP/3");
    (link, connection)
}

#[tokio::test]
async fn the_server_settings_reach_the_client() {
    let (_link, connection) = client(start_server()).await;
    let settings = connection.peer_settings().await.expect("SETTINGS");
    assert!(settings.enable_connect_protocol);
    assert!(settings.h3_datagram);
}

#[tokio::test]
async fn a_classic_connect_goes_without_scheme_and_path() {
    // Ровно то, на чём споткнулся `h3` в роли клиента (RFC 9114, §4.4).
    let (_link, connection) = client(start_server()).await;
    let mut stream = connection
        .send_request(&Request::connect("example.com:443").header("X-Echo", "Basic dXNlcg=="))
        .await
        .expect("запрос ушёл");
    let response = stream.response().await.expect("ответ");

    assert_eq!(response.status(), 200);
    assert_eq!(response.header("x-method"), Some("CONNECT"));
    assert_eq!(response.header("x-scheme"), Some("-"));
    assert_eq!(response.header("x-authority"), Some("example.com:443"));
    // Имя ушло строчным, значение — как есть, кодом Хаффмана или без.
    assert_eq!(response.header("x-echo"), Some("Basic dXNlcg=="));
}

#[tokio::test]
async fn the_body_goes_both_ways() {
    let (_link, connection) = client(start_server()).await;
    let mut stream = connection
        .send_request(&Request::connect("example.com:443"))
        .await
        .expect("запрос ушёл");
    stream.response().await.expect("ответ");

    let payload: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
    stream.write_all(&payload).await.expect("запись");
    stream.shutdown().await.expect("конец записи");

    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).await.expect("чтение");
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn an_extended_connect_carries_its_protocol() {
    let (_link, connection) = client(start_server()).await;
    let request =
        Request::extended_connect("connect-udp", "proxy:443", "/.well-known/masque/udp/a/53/");
    let mut stream = connection
        .send_request(&request)
        .await
        .expect("запрос ушёл");
    let response = stream.response().await.expect("ответ");

    assert_eq!(response.header("x-protocol"), Some("connect-udp"));
    assert_eq!(response.header("x-scheme"), Some("https"));
    assert_eq!(
        response.header("x-path"),
        Some("/.well-known/masque/udp/a/53/")
    );
    // Номер потока — первого двунаправленного потока клиента.
    assert_eq!(stream.id(), 0);
}

#[tokio::test]
async fn an_ordinary_request_with_a_body_is_answered() {
    let (_link, connection) = client(start_server()).await;
    let mut stream = connection
        .send_request(&Request::new("POST", "hysteria", "/auth"))
        .await
        .expect("запрос ушёл");
    stream.finish().expect("конец тела");
    let response = stream.response().await.expect("ответ");
    assert_eq!(response.header("x-method"), Some("POST"));
    assert_eq!(response.header("x-path"), Some("/auth"));
    assert_eq!(response.header("x-scheme"), Some("https"));
}

#[tokio::test]
async fn datagrams_go_only_when_both_sides_agree() {
    let (_link, connection) = client(start_server()).await;
    connection.peer_settings().await.expect("SETTINGS");
    assert!(connection.datagrams_available());
    connection.send_datagram(0, b"x").expect("датаграмма ушла");

    // Без своих датаграмм отправка не уходит в сеть вовсе.
    let (_link, plain) = client_with(start_server(), h3::Options::default()).await;
    plain.peer_settings().await.expect("SETTINGS");
    assert!(matches!(
        plain.send_datagram(0, b"x"),
        Err(H3Error::Unsupported(_))
    ));
}

#[tokio::test]
async fn xhttp_stream_one_carries_the_body_both_ways() {
    // Сервер — эхо, а не Xray: проверяется, что `stream-one` — обычный
    // поток HTTP/3, тело которого идёт туда и обратно, и что ответа он не
    // ждёт до первой записи.
    let server = start_server();
    let target = XhttpTarget {
        host: Address::Ip(server.ip()),
        port: server.port(),
        tls: TlsConfig {
            insecure: true,
            ..TlsConfig::default()
        },
        authority: "cdn.example.com".to_owned(),
        path: "/up".to_owned(),
    };
    let client = XhttpClient::new(target, Arc::new(Direct));

    for _ in 0..2 {
        // Второй поток — по тому же соединению QUIC.
        let mut stream = client.open().await.expect("поток");
        stream.write_all(b"ping").await.expect("запись");
        stream.shutdown().await.expect("конец записи");
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await.expect("чтение");
        assert_eq!(echoed, b"ping");
    }
    client.close().await;
}
