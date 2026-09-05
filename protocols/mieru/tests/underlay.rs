//! Соединение против поддельного сервера.
//!
//! Проверяется то, чего не видно по отдельным файлам: что открытие сессии,
//! данные и закрытие едут в правильном порядке и в правильном формате, и что
//! то, что шлёт клиент, читается независимо собранным шифром той же
//! стороны, — то есть что `SendCipher` клиента и `RecvCipher` «сервера»,
//! заведённые порознь от одного ключа, действительно понимают друг друга.
//!
//! Сервер здесь — половина [`tokio::io::duplex`], которая читает и пишет
//! сегменты через `cipher`/`segment` напрямую, в обход `Underlay`: так тест
//! проверяет провод, а не то, что клиент согласен сам с собой.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use penguin_mieru::cipher::{RecvCipher, SendCipher};
use penguin_mieru::error::MieruError;
use penguin_mieru::keying::Key;
use penguin_mieru::metadata::{
    self, DataAckKind, DataAckMetadata, Metadata, SessionKind, SessionMetadata,
};
use penguin_mieru::segment;
use penguin_mieru::underlay::Underlay;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// Сколько ждать сегмент, прежде чем считать, что его не будет.
const PATIENCE: Duration = Duration::from_secs(2);

fn key() -> Key {
    [9u8; 32]
}

/// Минут с начала эпохи — то же самое, что пишет в свои сегменты клиент.
fn now_minutes() -> u32 {
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 60) as u32
}

/// Сторона «сервера»: читает и пишет сегменты напрямую, без `Underlay`.
struct Server {
    io: DuplexStream,
    send: SendCipher,
    recv: RecvCipher,
}

impl Server {
    async fn recv(&mut self) -> (Metadata, Option<Vec<u8>>) {
        let m_len = segment::metadata_block_len(self.recv.expects_wire_nonce());
        let mut m_block = vec![0u8; m_len];
        tokio::time::timeout(PATIENCE, self.io.read_exact(&mut m_block))
            .await
            .expect("сегмент не пришёл")
            .expect("метаданные читаются");
        let metadata =
            segment::read_metadata(&mut self.recv, &m_block).expect("метаданные разбираются");

        if metadata.prefix_len() > 0 {
            let mut discard = vec![0u8; metadata.prefix_len() as usize];
            self.io
                .read_exact(&mut discard)
                .await
                .expect("дополнение читается");
        }
        let payload = if metadata.payload_len() > 0 {
            let p_len = segment::payload_block_len(metadata.payload_len());
            let mut p_block = vec![0u8; p_len];
            self.io
                .read_exact(&mut p_block)
                .await
                .expect("нагрузка читается");
            Some(segment::read_payload(&mut self.recv, &p_block).expect("нагрузка разбирается"))
        } else {
            None
        };
        if metadata.suffix_len() > 0 {
            let mut discard = vec![0u8; metadata.suffix_len() as usize];
            self.io
                .read_exact(&mut discard)
                .await
                .expect("дополнение читается");
        }
        (metadata, payload)
    }

    async fn send_raw(&mut self, metadata_bytes: [u8; metadata::LEN], payload: &[u8]) {
        let wire = segment::write(&mut self.send, &metadata_bytes, payload).expect("собирается");
        self.io.write_all(&wire).await.expect("пишется");
        self.io.flush().await.expect("уходит");
    }

    /// Принимает `openSessionRequest` и отвечает согласием.
    async fn accept_open(&mut self) -> u32 {
        let (metadata, _payload) = self.recv().await;
        let Metadata::Session(meta) = metadata else {
            panic!("ждали сегмент, управляющий сессией")
        };
        assert_eq!(meta.kind, SessionKind::OpenRequest);

        let response = SessionMetadata {
            kind: SessionKind::OpenResponse,
            timestamp_minutes: now_minutes(),
            session_id: meta.session_id,
            seq: 0,
            status: metadata::STATUS_OK,
            payload_len: 0,
            suffix_len: 0,
        };
        self.send_raw(response.encode(), &[]).await;
        meta.session_id
    }

    async fn refuse_open(&mut self, status: u8) -> u32 {
        let (metadata, _payload) = self.recv().await;
        let Metadata::Session(meta) = metadata else {
            panic!("ждали сегмент, управляющий сессией")
        };
        let response = SessionMetadata {
            kind: SessionKind::OpenResponse,
            timestamp_minutes: now_minutes(),
            session_id: meta.session_id,
            seq: 0,
            status,
            payload_len: 0,
            suffix_len: 0,
        };
        self.send_raw(response.encode(), &[]).await;
        meta.session_id
    }

    async fn send_data(&mut self, session_id: u32, payload: &[u8]) {
        let meta = DataAckMetadata {
            kind: DataAckKind::DataToClient,
            timestamp_minutes: now_minutes(),
            session_id,
            seq: 0,
            unack_seq: 0,
            window_size: 4096,
            fragment: 0,
            prefix_len: 0,
            payload_len: u16::try_from(payload.len()).unwrap(),
            suffix_len: 0,
        };
        self.send_raw(meta.encode(), payload).await;
    }

    async fn close_session(&mut self, session_id: u32) {
        let meta = SessionMetadata {
            kind: SessionKind::CloseRequest,
            timestamp_minutes: now_minutes(),
            session_id,
            seq: 0,
            status: 0,
            payload_len: 0,
            suffix_len: 0,
        };
        self.send_raw(meta.encode(), &[]).await;
    }
}

/// Поднимает клиентское соединение и отдаёт сторону поддельного сервера.
fn pair() -> (Arc<Underlay>, Server) {
    let (client, server_io) = tokio::io::duplex(64 * 1024);
    let underlay = Underlay::start(1, Box::new(client), &key(), Arc::from("alice"));
    let server = Server {
        io: server_io,
        send: SendCipher::new(&key(), "alice"),
        recv: RecvCipher::new(&key()),
    };
    (underlay, server)
}

#[tokio::test]
async fn opening_a_session_waits_for_the_servers_confirmation() {
    let (underlay, mut server) = pair();
    let opening = tokio::spawn(async move { underlay.open_session().await });

    server.accept_open().await;
    let stream = opening
        .await
        .expect("задача не падает")
        .expect("сессия открывается");
    assert!(stream.id() > 0);
}

#[tokio::test]
async fn quota_exhausted_is_reported_as_such_and_not_as_a_generic_disconnect() {
    let (underlay, mut server) = pair();
    let opening = tokio::spawn(async move { underlay.open_session().await });

    server.refuse_open(metadata::STATUS_QUOTA_EXHAUSTED).await;
    let err = opening
        .await
        .expect("задача не падает")
        .expect_err("сервер отказал");
    assert!(matches!(err, MieruError::QuotaExhausted), "{err}");
}

#[tokio::test]
async fn data_written_by_the_client_reaches_the_server_in_the_open_session() {
    let (underlay, mut server) = pair();
    let opening = tokio::spawn(async move { underlay.open_session().await });
    let session_id = server.accept_open().await;
    let mut stream = opening
        .await
        .expect("задача не падает")
        .expect("открывается");

    stream
        .write_all("привет".as_bytes())
        .await
        .expect("пишется");

    let (metadata, payload) = server.recv().await;
    let Metadata::DataAck(meta) = metadata else {
        panic!("ждали сегмент данных")
    };
    assert_eq!(meta.kind, DataAckKind::DataToServer);
    assert_eq!(meta.session_id, session_id);
    assert_eq!(payload.expect("нагрузка есть"), "привет".as_bytes());
}

#[tokio::test]
async fn data_from_the_server_reaches_the_stream_and_is_acknowledged() {
    let (underlay, mut server) = pair();
    let opening = tokio::spawn(async move { underlay.open_session().await });
    let session_id = server.accept_open().await;
    let mut stream = opening
        .await
        .expect("задача не падает")
        .expect("открывается");

    server.send_data(session_id, "ответ".as_bytes()).await;

    let mut got = vec![0u8; "ответ".len()];
    tokio::time::timeout(PATIENCE, stream.read_exact(&mut got))
        .await
        .expect("ответ не пришёл")
        .expect("читается");
    assert_eq!(got, "ответ".as_bytes());

    // Клиент обязан подтвердить получение — иначе сервер, соблюдающий окно
    // всерьёз, решит, что мы не читаем, и остановит поток.
    let (metadata, _payload) = server.recv().await;
    let Metadata::DataAck(meta) = metadata else {
        panic!("ждали подтверждение")
    };
    assert_eq!(meta.kind, DataAckKind::AckFromClient);
    assert_eq!(meta.unack_seq, 1);
}

#[tokio::test]
async fn a_close_from_the_server_ends_the_stream_without_an_error() {
    // Не ошибка: движок копирует до конца, и ошибка на месте конца выглядела
    // бы обрывом соединения в журнале, а не завершённым запросом.
    let (underlay, mut server) = pair();
    let opening = tokio::spawn(async move { underlay.open_session().await });
    let session_id = server.accept_open().await;
    let mut stream = opening
        .await
        .expect("задача не падает")
        .expect("открывается");

    server.send_data(session_id, b"tail").await;
    server.close_session(session_id).await;

    let mut got = Vec::new();
    tokio::time::timeout(PATIENCE, stream.read_to_end(&mut got))
        .await
        .expect("конец не пришёл")
        .expect("читается без ошибки");
    assert_eq!(got, b"tail");
}

#[tokio::test]
async fn dropping_the_stream_tells_the_server_to_close_the_session() {
    // Соединение держит открытым не поток, а пул (`Pool` в проде хранит свой
    // `Arc<Underlay>`, пока не решит его убрать), — иначе последний ушедший
    // поток обрывал бы задачу закрытия раньше, чем она успеет сказать
    // серверу. Здесь пула нет, и его роль на себя берёт `underlay`.
    let (underlay, mut server) = pair();
    let opening = tokio::spawn({
        let underlay = Arc::clone(&underlay);
        async move { underlay.open_session().await }
    });
    let session_id = server.accept_open().await;
    let stream = opening
        .await
        .expect("задача не падает")
        .expect("открывается");

    drop(stream);

    let (metadata, _payload) = server.recv().await;
    let Metadata::Session(meta) = metadata else {
        panic!("ждали сегмент, управляющий сессией")
    };
    assert_eq!(meta.kind, SessionKind::CloseRequest);
    assert_eq!(meta.session_id, session_id);
}

#[tokio::test]
async fn two_sessions_share_one_connection_and_keep_their_own_data() {
    let (underlay, mut server) = pair();

    let first_underlay = Arc::clone(&underlay);
    let opening_first = tokio::spawn(async move { first_underlay.open_session().await });
    let first_id = server.accept_open().await;
    let mut first = opening_first
        .await
        .expect("задача не падает")
        .expect("открывается");

    let opening_second = tokio::spawn(async move { underlay.open_session().await });
    let second_id = server.accept_open().await;
    let mut second = opening_second
        .await
        .expect("задача не падает")
        .expect("открывается");

    assert_ne!(first_id, second_id, "сессии обязаны получить разные номера");

    server.send_data(second_id, "второй".as_bytes()).await;
    server.send_data(first_id, "первый".as_bytes()).await;

    let mut got = vec![0u8; "второй".len()];
    second.read_exact(&mut got).await.expect("читается");
    assert_eq!(got, "второй".as_bytes());

    let mut got = vec![0u8; "первый".len()];
    first.read_exact(&mut got).await.expect("читается");
    assert_eq!(got, "первый".as_bytes());
}

#[tokio::test]
async fn a_server_that_vanished_is_a_broken_stream_and_not_a_clean_end() {
    let (underlay, mut server) = pair();
    let opening = tokio::spawn(async move { underlay.open_session().await });
    server.accept_open().await;
    let mut stream = opening
        .await
        .expect("задача не падает")
        .expect("открывается");

    drop(server);

    let mut got = Vec::new();
    let err = tokio::time::timeout(PATIENCE, stream.read_to_end(&mut got))
        .await
        .expect("обрыв не замечен")
        .expect_err("обрыв обязан быть ошибкой");
    assert!(!err.to_string().is_empty());
}
