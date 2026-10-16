//! TCP из тоннеля: имя восстанавливается обратным отображением fake-IP или
//! опознанием в потоке, затем маршрутизация и копирование. Опознанное имя
//! выбирает правило, но соединение идёт на исходный адрес.

use std::sync::Arc;

use penguin_core::address::{Address, SocketAddress};
use penguin_core::network::Network;
use penguin_dns::FakeIpMap;
use penguin_inbound::inbound::{InboundHandler, InboundRequest};
use penguin_netstack::{TcpConnection, TcpListener};
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
                tracing::debug!(%destination, %err, "соединение из тоннеля прервано");
            }
        });
    }
}

/// Ведёт одно соединение.
async fn serve(
    mut connection: TcpConnection,
    source: std::net::SocketAddr,
    destination: std::net::SocketAddr,
    pipeline: Arc<Pipeline>,
    fake_ip: Option<Arc<FakeIpMap>>,
    sniff_enabled: bool,
) -> std::io::Result<()> {
    let mut target = SocketAddress::from(destination);
    if let (Some(map), std::net::IpAddr::V4(v4)) = (&fake_ip, destination.ip())
        && let Some(domain) = map.domain_for(v4)
    {
        target = SocketAddress::new(Address::domain(&*domain), destination.port());
    }

    // Имя из потока — только для правил: оно может разрешаться не в этот адрес.
    let mut prefix = Vec::new();
    let mut sniffed = None;
    if sniff_enabled && !target.host.is_domain() {
        prefix = read_prefix(&mut connection).await;
        sniffed = sniff(Network::Tcp, &prefix);
    }

    let request = InboundRequest {
        source,
        target: target.clone(),
        sniffed,
        network: Network::Tcp,
    };
    let mut remote = pipeline
        .open_tcp(&request)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    remote.write_all(&prefix).await?;

    match relay(&mut connection, remote).await {
        Ok((uploaded, downloaded)) => {
            tracing::debug!(%target, uploaded, downloaded, "соединение закрыто");
            Ok(())
        }
        // Обрыв — сбросом: `FIN` выдал бы недописанный ответ за целый.
        Err(err) => {
            connection.abort();
            Err(err)
        }
    }
}

/// Читает первые байты для опознания имени; молчание — идём без имени.
async fn read_prefix<S: AsyncRead + Unpin>(connection: &mut S) -> Vec<u8> {
    let mut buffer = vec![0u8; SNIFF_LIMIT];

    match tokio::time::timeout(SNIFF_TIMEOUT, connection.read(&mut buffer)).await {
        Ok(Ok(read)) => {
            buffer.truncate(read);
            buffer
        }
        _ => Vec::new(),
    }
}

/// Перекачивает данные в обе стороны до закрытия обеих; полузакрытие не
/// обрывает хвост ответа.
pub async fn relay<A, B>(mut app: A, mut remote: B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    B: AsyncRead + AsyncWrite + Unpin + Send,
{
    tokio::io::copy_bidirectional_with_sizes(&mut app, &mut remote, COPY_BUFFER, COPY_BUFFER).await
}

/// Буфер на одно направление.
const COPY_BUFFER: usize = 16 * 1024;

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

        let (up, down) = relaying
            .await
            .expect("задача завершилась")
            .expect("без ошибок");
        assert_eq!(up, "запрос".len() as u64);
        assert_eq!(down, "ответ".len() as u64);
    }

    #[tokio::test]
    async fn half_close_does_not_cut_the_answer() {
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

        relaying
            .await
            .expect("задача завершилась")
            .expect("без ошибок");
    }

    #[tokio::test]
    async fn silent_connection_does_not_block_forever() {
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
