//! Сквозная проверка прокси-режима: через клиент проходят настоящие байты.
//!
//! Сервера нет: правила отправляют трафик напрямую, проверяется вся цепочка
//! кроме протокола.
//!
//! ```text
//!   тест ──► SOCKS5 ──► маршрутизатор ──► напрямую ──► тестовый сервер
//! ```

// Паника в тесте — провал, а не ошибка для обработки.
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

/// Приписка отличает ответ сервера от петли в буфере.
const ECHO_SUFFIX: &[u8] = b" <- back";

/// Поднимает эхо-сервер на настоящем сокете.
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

/// Поднимает SOCKS5, который всё отправляет напрямую (`TunnelMode::Off`).
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
            .with_process_lookup(false),
    );

    let inbound = Socks5Inbound::bind("127.0.0.1:0".parse().expect("адрес"), pipeline, None)
        .await
        .expect("прокси слушает");

    let addr = inbound.local_addr().expect("адрес известен");
    let cancel = CancellationToken::new();

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

    let SocketAddr::V4(target_v4) = target else {
        panic!("тестовый сервер обязан быть на IPv4");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target_v4.ip().octets());
    request.extend_from_slice(&target_v4.port().to_be_bytes());
    stream.write_all(&request).await.expect("запрос ушёл");

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.expect("ответ на запрос");
    assert_eq!(head[0], 0x05, "не тот номер версии в ответе");
    assert_eq!(
        head[1], 0x00,
        "прокси отказал в соединении: код {}",
        head[1]
    );

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
    let (proxy, cancel) = socks_proxy().await;

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
