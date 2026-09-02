//! TCP: принять, определить владельца, спросить маршрутизатор, соединить,
//! копировать.
//!
//! Сюда приходят соединения из тоннеля — уже собранные стеком, но ещё
//! безымянные: у них есть адрес назначения и нет имени. Имя восстанавливается
//! двумя способами, и оба нужны:
//!
//! 1. **обратным отображением fake-IP** — если приложение спрашивало адрес у
//!    нашего DNS;
//! 2. **опознанием в потоке** — если оно пришло с готовым адресом.

use std::sync::Arc;

use penguin_core::address::{Address, SocketAddress};
use penguin_core::network::Network;
use penguin_dns::FakeIpMap;
use penguin_inbound::inbound::{InboundHandler, InboundRequest};
use penguin_netstack::TcpListener;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::pipeline::Pipeline;
use crate::sniff::{SNIFF_LIMIT, SNIFF_TIMEOUT, sniff};

/// Принимает соединения из тоннеля и ведёт их через конвейер.
pub async fn pump(
    mut listener: TcpListener,
    pipeline: Arc<Pipeline>,
    fake_ip: Option<Arc<FakeIpMap>>,
    sniff_enabled: bool,
    cancel: CancellationToken,
) {
    loop {
        let accepted = tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            accepted = listener.accept() => accepted,
        };

        let Some(accepted) = accepted else { break };

        let pipeline = Arc::clone(&pipeline);
        let fake_ip = fake_ip.clone();

        tokio::spawn(async move {
            let source = accepted.source;
            let destination = accepted.destination;

            if let Err(err) = serve(
                accepted.connection,
                source,
                destination,
                pipeline,
                fake_ip,
                sniff_enabled,
            )
            .await
            {
                // Обычный фон: приложение передумало, вкладка закрылась.
                tracing::debug!(%destination, %err, "соединение из тоннеля прервано");
            }
        });
    }
}

/// Ведёт одно соединение.
async fn serve<S>(
    mut connection: S,
    source: std::net::SocketAddr,
    destination: std::net::SocketAddr,
    pipeline: Arc<Pipeline>,
    fake_ip: Option<Arc<FakeIpMap>>,
    sniff_enabled: bool,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // 1. Подставной адрес разворачивается обратно в имя. Это дешевле
    //    опознания в потоке и работает даже там, где имени в трафике нет
    //    вовсе.
    let mut target = SocketAddress::from(destination);
    if let (Some(map), std::net::IpAddr::V4(v4)) = (&fake_ip, destination.ip())
        && let Some(domain) = map.domain_for(v4)
    {
        target = SocketAddress::new(Address::domain(&*domain), destination.port());
    }

    // 2. Если имени всё ещё нет — заглядываем в первые байты.
    let mut prefix = Vec::new();
    if sniff_enabled && !target.host.is_domain() {
        prefix = read_prefix(&mut connection).await;
        if let Some(domain) = sniff(Network::Tcp, &prefix) {
            target = SocketAddress::new(domain, destination.port());
        }
    }

    let request = InboundRequest {
        source,
        target: target.clone(),
        network: Network::Tcp,
    };
    let remote = pipeline
        .open_tcp(&request)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let (mut remote_read, mut remote_write) = tokio::io::split(remote);

    // Прочитанное при опознании обязано уйти первым: это начало запроса
    // приложения, и потерять его — значит сломать соединение молча.
    if !prefix.is_empty() {
        remote_write.write_all(&prefix).await?;
    }

    let (mut app_read, mut app_write) = tokio::io::split(connection);
    let (up, down) = tokio::join!(
        async {
            let moved = tokio::io::copy(&mut app_read, &mut remote_write).await;
            let _ = remote_write.shutdown().await;
            moved
        },
        async {
            let moved = tokio::io::copy(&mut remote_read, &mut app_write).await;
            let _ = app_write.shutdown().await;
            moved
        }
    );

    tracing::debug!(
        %target,
        uploaded = up.unwrap_or(0),
        downloaded = down.unwrap_or(0),
        "соединение закрыто"
    );
    Ok(())
}

/// Читает первые байты для опознания имени.
///
/// Ждать бесконечно нельзя: приложение может открыть соединение и молчать,
/// ожидая приветствия сервера, — так делают, например, почтовые клиенты.
/// По истечении срока идём дальше без имени.
async fn read_prefix<S: AsyncRead + Unpin>(connection: &mut S) -> Vec<u8> {
    let mut buffer = vec![0u8; SNIFF_LIMIT];

    match tokio::time::timeout(SNIFF_TIMEOUT, connection.read(&mut buffer)).await {
        Ok(Ok(read)) => {
            buffer.truncate(read);
            buffer
        }
        // Молчание или ошибка — идём дальше без имени.
        _ => Vec::new(),
    }
}

/// Перекачивает данные между приложением и целью, пока обе стороны не закроются.
///
/// Обе половины качаются одновременно и до конца. Полузакрытое соединение —
/// законное состояние: приложение сказало «я всё отправил» и ждёт ответа.
/// Оборвать вторую половину, когда кончилась первая, значит потерять хвост
/// ответа — а это ровно то, на чём держится `HTTP/1.0` с `Connection: close`.
pub async fn relay<A, B>(app: A, remote: B) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    B: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut app_read, mut app_write) = tokio::io::split(app);
    let (mut remote_read, mut remote_write) = tokio::io::split(remote);

    let (up, down) = tokio::join!(
        async {
            let moved = tokio::io::copy(&mut app_read, &mut remote_write).await;
            // Закрытие на запись — аналог `FIN`: та сторона узнаёт, что данных
            // больше не будет, и может ответить и закрыться сама.
            let _ = remote_write.shutdown().await;
            moved
        },
        async {
            let moved = tokio::io::copy(&mut remote_read, &mut app_write).await;
            let _ = app_write.shutdown().await;
            moved
        }
    );

    (up.unwrap_or(0), down.unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    #[tokio::test]
    async fn moves_bytes_both_ways() {
        let (app, mut app_peer) = tokio::io::duplex(1024);
        let (remote, mut remote_peer) = tokio::io::duplex(1024);

        let relaying = tokio::spawn(relay(app, remote));

        app_peer
            .write_all("запрос".as_bytes())
            .await
            .expect("записано");
        app_peer.shutdown().await.expect("закрыто");

        let mut got = Vec::new();
        remote_peer.read_to_end(&mut got).await.expect("прочитано");
        assert_eq!(got, "запрос".as_bytes());

        remote_peer
            .write_all("ответ".as_bytes())
            .await
            .expect("записано");
        remote_peer.shutdown().await.expect("закрыто");

        let mut back = Vec::new();
        app_peer.read_to_end(&mut back).await.expect("прочитано");
        assert_eq!(back, "ответ".as_bytes());

        let (up, down) = relaying.await.expect("задача завершилась");
        assert_eq!(up, "запрос".len() as u64);
        assert_eq!(down, "ответ".len() as u64);
    }

    #[tokio::test]
    async fn half_close_does_not_cut_the_answer() {
        // Приложение отправило запрос и закрылось на запись; ответ обязан
        // дойти целиком.
        let (app, mut app_peer) = tokio::io::duplex(1024);
        let (remote, mut remote_peer) = tokio::io::duplex(1024);
        let relaying = tokio::spawn(relay(app, remote));

        app_peer.write_all(b"GET /").await.expect("записано");
        app_peer.shutdown().await.expect("закрыто");

        let mut request = Vec::new();
        remote_peer
            .read_to_end(&mut request)
            .await
            .expect("прочитано");

        let long_answer = vec![b'x'; 10_000];
        remote_peer.write_all(&long_answer).await.expect("записано");
        remote_peer.shutdown().await.expect("закрыто");

        let mut answer = Vec::new();
        app_peer.read_to_end(&mut answer).await.expect("прочитано");
        assert_eq!(answer.len(), long_answer.len());

        relaying.await.expect("задача завершилась");
    }

    #[tokio::test]
    async fn silent_connection_does_not_block_forever() {
        // Почтовый клиент открывает соединение и ждёт приветствия сервера.
        // Ждать его вечно — значит не соединиться никогда.
        let (mut connection, _peer) = tokio::io::duplex(1024);
        let started = std::time::Instant::now();

        let prefix = read_prefix(&mut connection).await;
        assert!(prefix.is_empty());
        assert!(started.elapsed() < SNIFF_TIMEOUT * 3, "ожидание затянулось");
    }

    #[tokio::test]
    async fn prefix_is_read_when_data_arrives() {
        let (mut connection, mut peer) = tokio::io::duplex(1024);
        peer.write_all(b"GET / HTTP/1.1\r\n")
            .await
            .expect("записано");

        let prefix = read_prefix(&mut connection).await;
        assert_eq!(prefix, b"GET / HTTP/1.1\r\n");
    }
}
