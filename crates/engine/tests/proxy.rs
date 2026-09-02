//! Сквозная проверка прокси-режима: через клиент проходят настоящие байты.
//!
//! Это тот путь, с которого начинается разбор любой неполадки («если через
//! `penguin socks` трафик ходит, а через тоннель нет — дело не в протоколе»),
//! и до сих пор он проверялся только по частям: рукопожатие SOCKS5 отдельно,
//! правила отдельно, копирование отдельно. Собранным целиком его никто не
//! проверял, а ломается он именно на стыках.
//!
//! Сервера здесь нет и не нужно: правила отправляют трафик **напрямую**, и
//! проверяется вся цепочка, кроме самого протокола, — приём соединения,
//! рукопожатие, разбор адреса, решение маршрутизатора, исходящее соединение и
//! перекачка байтов в обе стороны.
//!
//! ```text
//!   тест ──► SOCKS5 ──► маршрутизатор ──► напрямую ──► тестовый сервер
//! ```

// Вспомогательные функции этого файла паникуют вместо возврата ошибки, и это
// здесь верное поведение: непрочитавшийся образец или не собравшийся набор
// правил — не «ошибка, которую надо обработать», а провалившийся тест. Запрет
// `expect` заведён ради горячего пути, где паника рвёт соединение; в тестах
// обход его через `if let` даёт тест, молча проходящий при поломке.
#![allow(clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;

use penguin_config::schema::routing::{RoutingConfig, TunnelMode};
use penguin_core::id::OutboundId;
use penguin_dns::resolver::SystemResolver;
use penguin_engine::direct::SystemDialer;
use penguin_engine::metrics::counters::Metrics;
use penguin_engine::outbounds::OutboundPool;
use penguin_engine::pipeline::Pipeline;
use penguin_inbound::Socks5Inbound;
use penguin_inbound::inbound::Inbound;
use penguin_process::resolver::NoResolver;
use penguin_router::engine::Router;
use penguin_router::ruleset::CompileContext;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// Что тестовый сервер приписывает к полученному.
///
/// Приписка нужна, чтобы отличить «дошло и вернулось» от «прочитали то, что
/// сами же и отправили»: без неё эхо неотличимо от петли в буфере.
const ECHO_SUFFIX: &[u8] = b" <- back";

/// Поднимает сервер, который отвечает на всё, что ему прислали.
///
/// Настоящий сокет, а не заглушка: проверяется в том числе то, что клиент
/// умеет открыть исходящее соединение и довести до него байты.
async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("сервер слушает");
    let addr = listener.local_addr().expect("адрес известен");

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 512];
                while let Ok(read) = stream.read(&mut buffer).await {
                    if read == 0 {
                        break;
                    }
                    let mut answer = buffer[..read].to_vec();
                    answer.extend_from_slice(ECHO_SUFFIX);
                    if stream.write_all(&answer).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    addr
}

/// Поднимает SOCKS5, который всё отправляет напрямую.
///
/// `TunnelMode::Off` — режим «тоннель выключен, правила продолжают
/// разбираться»: ровно то, что нужно, чтобы проверить всю цепочку без сервера.
async fn socks_proxy() -> (SocketAddr, CancellationToken) {
    let dialer = Arc::new(SystemDialer::new(Arc::new(SystemResolver)));
    let outbounds = Arc::new(OutboundPool::new(dialer));

    let routing = RoutingConfig {
        mode: TunnelMode::Off,
        ..RoutingConfig::default()
    };
    let router = Arc::new(
        Router::new(&routing, OutboundId::direct(), &CompileContext::default())
            .expect("правила собираются"),
    );

    let pipeline = Arc::new(
        Pipeline::new(router, outbounds, Arc::new(NoResolver), Metrics::new())
            // Владелец соединения не ищется: правил по процессам нет, а
            // системный вызов на каждое соединение стоит денег.
            .with_process_lookup(false),
    );

    let inbound = Socks5Inbound::bind("127.0.0.1:0".parse().expect("адрес"), pipeline, None)
        .await
        .expect("прокси слушает");

    let addr = inbound.local_addr().expect("адрес известен");
    let cancel = CancellationToken::new();

    // `serve` берёт точку по значению в боксе: она работает, пока её не
    // остановят, и делить её с кем-то незачем.
    let inbound: Box<dyn Inbound> = Box::new(inbound);
    tokio::spawn({
        let cancel = cancel.clone();
        async move {
            inbound.serve(cancel).await;
        }
    });

    (addr, cancel)
}

/// Проходит рукопожатие SOCKS5 и просит соединение с `target`.
async fn socks_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy)
        .await
        .expect("прокси принял соединение");

    // Приветствие: версия 5, один метод — без пароля.
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("приветствие ушло");
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .expect("ответ на приветствие");
    assert_eq!(
        greeting,
        [0x05, 0x00],
        "прокси не согласился работать без пароля"
    );

    // Запрос CONNECT на адрес IPv4.
    let SocketAddr::V4(target_v4) = target else {
        panic!("тестовый сервер обязан быть на IPv4");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target_v4.ip().octets());
    request.extend_from_slice(&target_v4.port().to_be_bytes());
    stream.write_all(&request).await.expect("запрос ушёл");

    // Ответ: версия, код, резерв, тип адреса, адрес, порт.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.expect("ответ на запрос");
    assert_eq!(head[0], 0x05, "не тот номер версии в ответе");
    assert_eq!(
        head[1], 0x00,
        "прокси отказал в соединении: код {}",
        head[1]
    );

    // Дочитываем привязанный адрес, иначе он попадёт в поток данных.
    let mut bound = [0u8; 6];
    stream
        .read_exact(&mut bound)
        .await
        .expect("привязанный адрес");

    stream
}

#[tokio::test]
async fn bytes_travel_through_the_proxy_in_both_directions() {
    let target = echo_server().await;
    let (proxy, cancel) = socks_proxy().await;

    let mut stream = socks_connect(proxy, target).await;

    stream
        .write_all("привет".as_bytes())
        .await
        .expect("запрос ушёл");

    let expected = {
        let mut bytes = "привет".as_bytes().to_vec();
        bytes.extend_from_slice(ECHO_SUFFIX);
        bytes
    };
    let mut answer = vec![0u8; expected.len()];
    stream.read_exact(&mut answer).await.expect("ответ пришёл");

    assert_eq!(answer, expected, "через прокси пришло не то, что отправили");
    cancel.cancel();
}

#[tokio::test]
async fn the_proxy_survives_several_connections() {
    // Прокси на одно соединение бесполезен: браузер открывает их десятками.
    let target = echo_server().await;
    let (proxy, cancel) = socks_proxy().await;

    for step in 0..5u8 {
        let mut stream = socks_connect(proxy, target).await;
        let sent = [step; 4];

        stream.write_all(&sent).await.expect("запрос ушёл");

        let mut answer = vec![0u8; sent.len() + ECHO_SUFFIX.len()];
        stream.read_exact(&mut answer).await.expect("ответ пришёл");
        assert_eq!(
            &answer[..sent.len()],
            &sent,
            "соединение {step} перепутало данные"
        );
    }

    cancel.cancel();
}

#[tokio::test]
async fn a_refused_target_is_reported_not_hung() {
    // Соединение, которое не открылось, обязано вернуть отказ. Молчание в
    // ответ выглядит для приложения как зависшая сеть, и ждать оно будет
    // долго.
    let (proxy, cancel) = socks_proxy().await;

    // Порт, который заведомо никто не слушает: занимаем и сразу отпускаем.
    let dead = {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("слушает");
        listener.local_addr().expect("адрес известен")
    };

    let mut stream = TcpStream::connect(proxy)
        .await
        .expect("прокси принял соединение");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("приветствие ушло");
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .expect("ответ на приветствие");

    let SocketAddr::V4(dead_v4) = dead else {
        panic!("нужен IPv4")
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&dead_v4.ip().octets());
    request.extend_from_slice(&dead_v4.port().to_be_bytes());
    stream.write_all(&request).await.expect("запрос ушёл");

    let mut head = [0u8; 4];
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut head),
    )
    .await
    .expect("прокси не ответил за пять секунд — приложение решило бы, что сеть зависла");

    read.expect("ответ прочитан");
    assert_eq!(head[0], 0x05);
    assert_ne!(
        head[1], 0x00,
        "прокси отчитался об успехе там, где соединения нет"
    );

    cancel.cancel();
}
