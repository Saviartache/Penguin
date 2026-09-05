//! Клиент против поддельного сервера — через настоящий сокет.
//!
//! Проверяется то, чего не видно по отдельным файлам: что соль, заголовок,
//! обфускация и ответ складываются в правильном порядке и что данные доходят
//! до обеих сторон. Сервер здесь свой — значит проверка ловит ошибку сборки
//! слоёв, но не ошибку понимания протокола; для второго есть `scripts/interop`.

// Проверка падает там, где сервер повёл себя не по протоколу: это не
// «ошибка, которую надо обработать», а провалившийся тест.
#![allow(clippy::expect_used)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use penguin_core::address::SocketAddress;
use penguin_core::id::OutboundId;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::stream::ProxyStream;
use penguin_snell::chunks::Chunks;
use penguin_snell::config::SnellConfig;
use penguin_snell::crypto;
use penguin_snell::frame::{reply, udp};
use penguin_snell::outbound::SnellOutbound;
use penguin_snell::v4::V4Stream;
use penguin_snell::version::Version;
use penguin_transport::aead::ChunkStream;
use penguin_transport::obfs::Mode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Пароль, общий у обеих сторон.
const PSK: &str = "общий ключ";

/// Сколько ждать, прежде чем считать, что сторона молчит.
const PATIENCE: Duration = Duration::from_secs(5);

/// Звонящий, который ходит по настоящему сокету до нашего же слушателя.
#[derive(Debug)]
struct LocalDialer;

#[async_trait::async_trait]
impl Dialer for LocalDialer {
    async fn dial_tcp(&self, addr: SocketAddr) -> Result<TcpStream, ProtocolError> {
        TcpStream::connect(addr)
            .await
            .map_err(|e| ProtocolError::Connect(e.to_string()))
    }

    async fn bind_udp(&self, _local: SocketAddr) -> Result<UdpSocket, ProtocolError> {
        Err(ProtocolError::Unsupported("UDP наружу в тесте не нужен"))
    }

    async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, ProtocolError> {
        Err(ProtocolError::Unsupported("имён в тесте нет"))
    }
}

/// Поддельный сервер: слушает, снимает обфускацию и говорит по протоколу.
struct Server {
    listener: TcpListener,
    version: Version,
    obfs: Mode,
}

impl Server {
    /// Поднимает слушателя на свободном порту.
    async fn start(version: Version, obfs: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("слушается");
        Self {
            listener,
            version,
            obfs,
        }
    }

    /// Адрес для настроек клиента.
    fn address(&self) -> String {
        self.listener.local_addr().expect("адрес").to_string()
    }

    /// Принимает соединение и снимает с него обфускацию.
    ///
    /// Возвращает поток кусками: обе стороны говорят одинаково, а каким
    /// кадром — решает версия.
    async fn accept(&self) -> Box<dyn Chunks> {
        let (mut io, _) = self.listener.accept().await.expect("принято");

        if self.obfs == Mode::Http {
            // Сервер обфускации ищет конец заголовков и отвечает своим.
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                io.read_exact(&mut byte).await.expect("заголовки");
                head.push(byte[0]);
            }
            io.write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
                .await
                .expect("отвечено");
        }

        let keying = crypto::keying(PSK.to_owned(), self.version.algorithm());
        let salt = vec![9u8; crypto::SALT_LEN];
        let send = keying.cipher(&salt).expect("ключ выводится");
        let io: Box<dyn ProxyStream> = Box::new(io);

        if self.version.framed() {
            // Соль уедет с первым кадром: у своего кадра так.
            return Box::new(V4Stream::new(io, keying, salt, send));
        }

        // У общего кадра соль идёт вперёд отдельной записью.
        let mut io = io;
        io.write_all(&salt).await.expect("соль ушла");
        Box::new(ChunkStream::new(io, keying, send))
    }
}

/// Собирает направление под этот сервер.
fn outbound(server: &Server, udp: bool) -> SnellOutbound {
    let config = SnellConfig {
        server: server.address(),
        psk: PSK.to_owned(),
        version: server.version,
        obfs: server.obfs,
        obfs_host: (server.obfs != Mode::None).then(|| "bing.com".to_owned()),
        udp,
    };
    SnellOutbound::new(
        OutboundId::from("тест".to_owned()),
        config,
        Arc::new(LocalDialer),
    )
    .expect("собирается")
}

#[tokio::test]
async fn the_header_reaches_the_server_and_the_data_goes_both_ways() {
    for version in [
        Version::V1,
        Version::V2,
        Version::V3,
        Version::V4,
        Version::V5,
    ] {
        let server = Server::start(version, Mode::None).await;
        let outbound = outbound(&server, false);

        let waiting = tokio::spawn(async move {
            let mut side = server.accept().await;
            let header = side
                .read_chunk()
                .await
                .expect("читается")
                .expect("заголовок");

            side.write_chunk(&[reply::TUNNEL])
                .await
                .expect("ответ ушёл");
            let data = side.read_chunk().await.expect("читается").expect("данные");
            side.write_chunk("ответ".as_bytes()).await.expect("ушло");
            (header.to_vec(), data.to_vec())
        });

        let target = SocketAddress::domain("example.com", 443);
        let mut stream = outbound.connect_tcp(&target).await.expect("подключается");
        stream
            .write_all("запрос".as_bytes())
            .await
            .expect("пишется");
        stream.flush().await.expect("уходит");

        let mut got = vec![0u8; "ответ".len()];
        tokio::time::timeout(PATIENCE, stream.read_exact(&mut got))
            .await
            .expect("ответ не пришёл")
            .expect("читается");
        assert_eq!(got, "ответ".as_bytes(), "{version}");

        let (header, data) = waiting.await.expect("задача");
        assert_eq!(header[0], 1, "версия в заголовке, {version}");
        assert_eq!(
            header[1],
            if version == Version::V2 { 5 } else { 1 },
            "команда, {version}"
        );
        assert_eq!(&header[4..15], b"example.com", "{version}");
        assert_eq!(data, "запрос".as_bytes(), "{version}");
    }
}

#[tokio::test]
async fn the_obfuscation_changes_the_wire_and_not_what_arrives() {
    let server = Server::start(Version::V3, Mode::Http).await;
    let outbound = outbound(&server, false);

    let waiting = tokio::spawn(async move {
        let mut side = server.accept().await;
        let header = side
            .read_chunk()
            .await
            .expect("читается")
            .expect("заголовок");
        side.write_chunk(&[reply::TUNNEL])
            .await
            .expect("ответ ушёл");
        side.write_chunk(b"through").await.expect("ушло");
        header.to_vec()
    });

    let target = SocketAddress::domain("example.com", 80);
    let mut stream = outbound.connect_tcp(&target).await.expect("подключается");

    let mut got = [0u8; 7];
    tokio::time::timeout(PATIENCE, stream.read_exact(&mut got))
        .await
        .expect("ответ не пришёл")
        .expect("читается");
    assert_eq!(&got, b"through");

    let header = waiting.await.expect("задача");
    assert_eq!(&header[4..15], b"example.com");
}

#[tokio::test]
async fn a_refusal_from_the_server_reaches_the_application() {
    let server = Server::start(Version::V3, Mode::None).await;
    let outbound = outbound(&server, false);

    tokio::spawn(async move {
        let mut side = server.accept().await;
        let _ = side.read_chunk().await;

        let mut answer = vec![reply::ERROR, 3, 11];
        answer.extend_from_slice(b"no such dns");
        side.write_chunk(&answer).await.expect("отказ ушёл");
    });

    let target = SocketAddress::domain("nowhere.invalid", 443);
    let mut stream = outbound.connect_tcp(&target).await.expect("подключается");

    let mut got = Vec::new();
    let err = tokio::time::timeout(PATIENCE, stream.read_to_end(&mut got))
        .await
        .expect("отказ не пришёл")
        .expect_err("это отказ");
    assert!(err.to_string().contains("no such dns"), "{err}");
}

#[tokio::test]
async fn a_wrong_psk_looks_like_a_refusal_and_not_like_a_broken_link() {
    let server = Server::start(Version::V3, Mode::None).await;
    let mut config = SnellConfig {
        server: server.address(),
        psk: "не тот ключ".to_owned(),
        version: Version::V3,
        ..SnellConfig::default()
    };
    config.udp = false;

    tokio::spawn(async move {
        let mut side = server.accept().await;
        // Сервер с другим ключом не расшифрует заголовок; здесь он просто
        // отвечает своим, и метка не сойдётся уже у клиента.
        let _ = side.write_chunk(&[reply::TUNNEL]).await;
        tokio::time::sleep(PATIENCE).await;
    });

    let outbound = SnellOutbound::new(
        OutboundId::from("тест".to_owned()),
        config,
        Arc::new(LocalDialer),
    )
    .expect("собирается");

    let target = SocketAddress::domain("example.com", 443);
    let mut stream = outbound.connect_tcp(&target).await.expect("подключается");

    let mut got = Vec::new();
    let err = tokio::time::timeout(PATIENCE, stream.read_to_end(&mut got))
        .await
        .expect("ответ не пришёл")
        .expect_err("метка не сошлась");
    assert!(err.to_string().contains("метка подлинности"), "{err}");
}

#[tokio::test]
async fn datagrams_go_out_and_come_back() {
    let server = Server::start(Version::V3, Mode::None).await;
    let outbound = outbound(&server, true);

    let waiting = tokio::spawn(async move {
        let mut side = server.accept().await;
        let header = side
            .read_chunk()
            .await
            .expect("читается")
            .expect("заголовок");

        // Готовность и первая посылка — разными кусками: так бывает.
        side.write_chunk(&[reply::TUNNEL]).await.expect("готов");

        let sent = side.read_chunk().await.expect("читается").expect("посылка");

        let mut answer = vec![udp::ATYP_IPV4, 203, 0, 113, 5];
        answer.extend_from_slice(&53u16.to_be_bytes());
        answer.extend_from_slice(b"answer");
        side.write_chunk(&answer).await.expect("ответ ушёл");

        (header.to_vec(), sent.to_vec())
    });

    let channel = outbound.bind_udp().await.expect("канал открывается");
    let target = SocketAddress::domain("dns.example.com", 53);
    channel
        .send_to(bytes::Bytes::from_static(b"query"), &target)
        .await
        .expect("уходит");

    let (payload, from) = tokio::time::timeout(PATIENCE, channel.recv_from())
        .await
        .expect("ответ не пришёл")
        .expect("читается");
    assert_eq!(payload, bytes::Bytes::from_static(b"answer"));
    assert_eq!(from.port, 53);
    assert_eq!(
        from.host.as_ip().map(|ip| ip.to_string()).as_deref(),
        Some("203.0.113.5")
    );

    let (header, sent) = waiting.await.expect("задача");
    assert_eq!(header, [1, 6, 0], "заголовок канала датаграмм");
    assert_eq!(sent[0], udp::FORWARD);
    assert_eq!(sent[1], "dns.example.com".len() as u8);
    assert_eq!(&sent[2..17], b"dns.example.com");
    assert_eq!(&sent[17..19], &53u16.to_be_bytes());
    assert_eq!(&sent[19..], b"query");
}

#[tokio::test]
async fn a_refusal_on_the_datagram_channel_is_not_silent() {
    let server = Server::start(Version::V3, Mode::None).await;
    let outbound = outbound(&server, true);

    tokio::spawn(async move {
        let mut side = server.accept().await;
        let _ = side.read_chunk().await;

        let mut answer = vec![reply::ERROR, 1, 7];
        answer.extend_from_slice(b"no ports");
        let _ = side.write_chunk(&answer[..3 + 7]).await;
        tokio::time::sleep(PATIENCE).await;
    });

    let channel = outbound.bind_udp().await.expect("канал открывается");
    let err = tokio::time::timeout(PATIENCE, channel.recv_from())
        .await
        .expect("отказ не пришёл")
        .expect_err("это отказ");
    assert!(err.to_string().contains("сервер отказал"), "{err}");
}

#[tokio::test]
async fn a_version_that_cannot_do_udp_refuses_before_the_socket() {
    let server = Server::start(Version::V1, Mode::None).await;
    let outbound = outbound(&server, true);

    let Err(err) = outbound.bind_udp().await else {
        panic!("первая версия не умеет UDP, а канал открылся");
    };
    assert!(matches!(err, ProtocolError::Unsupported("UDP")));
}
