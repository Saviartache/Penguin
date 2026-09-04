//! Сессия против поддельного сервера.
//!
//! Проверяется то, чего не видно по отдельным файлам: что настройки, открытие
//! потока и данные уезжают в правильном порядке, что дополнение при этом
//! никому не мешает, и что ответы сервера доходят до потока.
//!
//! Сервер здесь — половина [`tokio::io::duplex`], которая читает кадры и
//! отвечает кадрами. Настоящего TLS нет и не нужно: своего шифрования у
//! AnyTLS не бывает, и всё, что ниже кадров, — чужая забота.

// Проверка падает там, где сервер повёл себя не по протоколу: это не
// «ошибка, которую надо обработать», а провалившийся тест. Запрет `expect`
// заведён ради пути соединения, где паника рвёт тоннель.
#![allow(clippy::expect_used)]

use std::sync::{Arc, Weak};
use std::time::Duration;

use penguin_anytls::frame::{self, HEADER_LEN, Header};
use penguin_anytls::kv::Map;
use penguin_anytls::padding::Padding;
use penguin_anytls::session::Session;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// Сколько ждать кадра, прежде чем считать, что его не будет.
const PATIENCE: Duration = Duration::from_secs(2);

/// Поднимает сессию и отдаёт сторону сервера.
fn pair() -> (Arc<Session>, DuplexStream) {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let session = Session::start(
        1,
        Box::new(client),
        Arc::new(Padding::new()),
        "penguin/тест",
        Weak::new(),
    )
    .expect("сессия поднимается");
    (session, server)
}

/// Читает следующий кадр со стороны сервера.
async fn frame_of(io: &mut DuplexStream) -> (u8, u32, Vec<u8>) {
    let mut head = [0_u8; HEADER_LEN];
    tokio::time::timeout(PATIENCE, io.read_exact(&mut head))
        .await
        .expect("кадр не пришёл")
        .expect("заголовок читается");

    let header = Header::decode(&head);
    let mut data = vec![0_u8; usize::from(header.len)];
    if !data.is_empty() {
        io.read_exact(&mut data).await.expect("данные читаются");
    }
    (header.cmd, header.sid, data)
}

/// То же, но мимо дополнения: оно едет теми же кадрами и смысла не несёт.
async fn payload_of(io: &mut DuplexStream) -> (u8, u32, Vec<u8>) {
    loop {
        let got = frame_of(io).await;
        if got.0 != frame::CMD_WASTE {
            return got;
        }
    }
}

/// Отправляет кадр со стороны сервера.
async fn reply(io: &mut DuplexStream, cmd: u8, sid: u32, data: &[u8]) {
    let bytes = frame::encode(cmd, sid, data).expect("кадр собирается");
    io.write_all(&bytes).await.expect("пишется");
    io.flush().await.expect("уходит");
}

#[tokio::test]
async fn the_session_introduces_itself_before_anything_else() {
    let (session, mut server) = pair();
    let mut stream = session.open_stream().await.expect("поток открывается");
    stream.write_all(b"hi").await.expect("пишется");

    let (cmd, sid, data) = payload_of(&mut server).await;
    assert_eq!(cmd, frame::CMD_SETTINGS, "первым идёт не кадр настроек");
    assert_eq!(sid, 0);

    let settings = Map::parse(&data);
    assert_eq!(settings.get("v"), Some("2"));
    assert_eq!(settings.get("client"), Some("penguin/тест"));
    // Отпечаток схемы по умолчанию: по нему сервер решает, присылать ли свою.
    assert_eq!(
        settings.get("padding-md5"),
        Some("75cff2ad89aadf5e257059ee571ebe11")
    );

    assert_eq!(payload_of(&mut server).await, (frame::CMD_SYN, 1, vec![]));
    assert_eq!(
        payload_of(&mut server).await,
        (frame::CMD_PSH, 1, b"hi".to_vec())
    );
}

#[tokio::test]
async fn the_first_record_carries_the_beginning_of_the_conversation_at_once() {
    // Настройки, открытие потока и первые данные обязаны уехать одной
    // записью: схема дополнения считает их одним пакетом, и по отдельности
    // они выглядят иначе.
    let (session, mut server) = pair();
    let mut stream = session.open_stream().await.expect("поток открывается");
    stream.write_all(b"hi").await.expect("пишется");

    let mut first = vec![0_u8; 512];
    let read = tokio::time::timeout(PATIENCE, server.read(&mut first))
        .await
        .expect("запись не пришла")
        .expect("читается");
    first.truncate(read);

    // Схема по умолчанию отводит первому пакету от 100 до 400 байт — на «hi»
    // это почти целиком дополнение.
    assert!((100..400).contains(&read), "запись в {read} байт");
    assert_eq!(first[0], frame::CMD_SETTINGS);
    assert!(
        first.windows(2).any(|pair| pair == b"hi"),
        "данные не уехали вместе с началом"
    );
}

#[tokio::test]
async fn an_answer_from_the_server_reaches_the_stream() {
    let (session, mut server) = pair();
    let mut stream = session.open_stream().await.expect("поток открывается");
    stream.write_all(b"hi").await.expect("пишется");
    let _ = payload_of(&mut server).await;

    reply(&mut server, frame::CMD_PSH, 1, "ответ".as_bytes()).await;

    let mut got = vec![0_u8; "ответ".len()];
    tokio::time::timeout(PATIENCE, stream.read_exact(&mut got))
        .await
        .expect("ответ не пришёл")
        .expect("читается");
    assert_eq!(got, "ответ".as_bytes());
}

#[tokio::test]
async fn a_close_from_the_server_is_the_end_of_the_stream_and_not_a_failure() {
    // Именно не ошибка: движок копирует до конца, и ошибка на месте конца
    // выглядела бы обрывом соединения в журнале.
    let (session, mut server) = pair();
    let mut stream = session.open_stream().await.expect("поток открывается");
    stream.write_all(b"hi").await.expect("пишется");

    reply(&mut server, frame::CMD_PSH, 1, b"tail").await;
    reply(&mut server, frame::CMD_FIN, 1, &[]).await;

    let mut got = Vec::new();
    tokio::time::timeout(PATIENCE, stream.read_to_end(&mut got))
        .await
        .expect("конец не пришёл")
        .expect("читается без ошибки");
    assert_eq!(got, b"tail");
}

#[tokio::test]
async fn a_stream_nobody_holds_any_more_is_closed_for_the_server_too() {
    let (session, mut server) = pair();
    let mut stream = session.open_stream().await.expect("поток открывается");
    stream.write_all(b"hi").await.expect("пишется");
    let _ = payload_of(&mut server).await;
    let _ = payload_of(&mut server).await;
    let _ = payload_of(&mut server).await;

    drop(stream);
    assert_eq!(payload_of(&mut server).await, (frame::CMD_FIN, 1, vec![]));
}

#[tokio::test]
async fn shutting_the_stream_down_does_not_close_it() {
    // Полузакрытия у AnyTLS нет: `cmdFIN` закрывает поток в обе стороны, и
    // послать его на `shutdown` значило бы потерять ответ сервера.
    let (session, mut server) = pair();
    let mut stream = session.open_stream().await.expect("поток открывается");
    stream.write_all(b"hi").await.expect("пишется");
    stream.shutdown().await.expect("сбрасывается");

    reply(&mut server, frame::CMD_PSH, 1, b"late").await;

    let mut got = vec![0_u8; 4];
    tokio::time::timeout(PATIENCE, stream.read_exact(&mut got))
        .await
        .expect("ответ не пришёл")
        .expect("читается");
    assert_eq!(got, b"late");
}

#[tokio::test]
async fn a_heartbeat_is_answered() {
    let (session, mut server) = pair();
    let mut stream = session.open_stream().await.expect("поток открывается");
    stream.write_all(b"hi").await.expect("пишется");
    let _ = payload_of(&mut server).await;

    reply(&mut server, frame::CMD_HEART_REQUEST, 0, &[]).await;
    loop {
        let (cmd, ..) = payload_of(&mut server).await;
        if cmd == frame::CMD_HEART_RESPONSE {
            break;
        }
        assert_ne!(cmd, frame::CMD_ALERT, "сессия закрылась вместо ответа");
    }
}

#[tokio::test]
async fn a_scheme_from_the_server_replaces_the_default_one() {
    let (session, mut server) = pair();
    let before = session.padding().get().md5().to_owned();

    reply(
        &mut server,
        frame::CMD_UPDATE_PADDING,
        0,
        b"stop=4\n1=200-200",
    )
    .await;

    // Схему принимает задача чтения: ждём, пока она это заметит.
    for _ in 0..200 {
        if session.padding().get().md5() != before {
            assert_eq!(session.padding().get().stop(), 4);
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("схема не принята");
}

#[tokio::test]
async fn the_version_of_the_server_is_learned_from_its_settings() {
    let (session, mut server) = pair();
    assert_eq!(session.peer_version(), 0, "версия известна до ответа");

    reply(&mut server, frame::CMD_SERVER_SETTINGS, 0, b"v=2").await;

    for _ in 0..200 {
        if session.peer_version() == 2 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("версия сервера не принята");
}

#[tokio::test]
async fn a_refusal_from_the_server_closes_the_session() {
    let (session, mut server) = pair();
    let mut stream = session.open_stream().await.expect("поток открывается");

    reply(&mut server, frame::CMD_ALERT, 0, b"too many sessions").await;

    let mut got = Vec::new();
    let err = tokio::time::timeout(PATIENCE, stream.read_to_end(&mut got))
        .await
        .expect("сессия не закрылась")
        .expect_err("отказ обязан быть ошибкой");
    assert!(err.to_string().contains("too many sessions"), "{err}");
    assert!(session.is_dead());
}

#[tokio::test]
async fn a_refusal_to_open_a_stream_comes_out_as_its_error() {
    // Подтверждение с данными — это отказ: сервер объяснил, почему не смог
    // соединиться. Показать это пустым ответом значило бы соврать.
    let (session, mut server) = pair();
    let mut stream = session.open_stream().await.expect("поток открывается");
    stream.write_all(b"hi").await.expect("пишется");

    reply(&mut server, frame::CMD_SYN_ACK, 1, b"connection refused").await;

    let mut got = Vec::new();
    let err = tokio::time::timeout(PATIENCE, stream.read_to_end(&mut got))
        .await
        .expect("ответ не пришёл")
        .expect_err("отказ обязан быть ошибкой");
    assert!(err.to_string().contains("refused"), "{err}");
}

#[tokio::test]
async fn a_server_that_vanished_is_a_broken_stream_and_not_an_end() {
    let (session, server) = pair();
    let mut stream = session.open_stream().await.expect("поток открывается");
    drop(server);

    let mut got = Vec::new();
    let err = tokio::time::timeout(PATIENCE, stream.read_to_end(&mut got))
        .await
        .expect("обрыв не замечен")
        .expect_err("обрыв обязан быть ошибкой");
    assert!(!err.to_string().is_empty());
}

#[tokio::test]
async fn streams_are_numbered_from_one_and_keep_their_own_data() {
    let (session, mut server) = pair();
    let mut first = session.open_stream().await.expect("первый");
    let mut second = session.open_stream().await.expect("второй");
    first.write_all(b"one").await.expect("пишется");
    second.write_all(b"two").await.expect("пишется");

    reply(&mut server, frame::CMD_PSH, 2, "второму".as_bytes()).await;
    reply(&mut server, frame::CMD_PSH, 1, "первому".as_bytes()).await;

    let mut got = vec![0_u8; "второму".len()];
    second.read_exact(&mut got).await.expect("читается");
    assert_eq!(got, "второму".as_bytes());

    let mut got = vec![0_u8; "первому".len()];
    first.read_exact(&mut got).await.expect("читается");
    assert_eq!(got, "первому".as_bytes());
}
