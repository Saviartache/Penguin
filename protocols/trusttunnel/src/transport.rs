//! Соединение с сервером: TCP, TLS, рукопожатие HTTP/2.
//!
//! HTTP/3 не реализован (см. документацию крейта) — этот модуль поднимает
//! только TCP+TLS+`h2`, устроенный так же, как `protocols/naive` (фаза 12),
//! которая ходит `CONNECT`-туннелем тем же способом.
//!
//! Сокет не открывается здесь напрямую: TUN перехватывает весь трафик
//! машины, и сокет, открытый в обход [`Dialer`], отправил бы рукопожатие в
//! собственный, ещё не поднятый тоннель (`AGENTS.md`, §3).

use bytes::Bytes;
use h2::client::SendRequest;
use penguin_core::address::Address;
use penguin_proto::connect as dial;
use penguin_proto::dialer::Dialer;
use penguin_transport::deadline;
use penguin_transport::tls::{ALPN_H2, TlsClient};
use tokio::task::JoinHandle;

use crate::config::TrustTunnelConfig;
use crate::error::{TrustTunnelError, TrustTunnelResult};

/// Начальный размер окна потока HTTP/2: 131072 байта (`PROTOCOL.md`, §3.1) —
/// умолчание Chrome. Маскировка держится на том, что рукопожатие неотличимо
/// от браузера, и окно по умолчанию `h2` (65535) выдало бы клиента первым же
/// `SETTINGS`-кадром.
const INITIAL_WINDOW_SIZE: u32 = 131_072;

/// Отправитель запросов HTTP/2.
///
/// Клонируется — им открывается и поток `CONNECT` на каждый TCP-адрес, и
/// (один раз) поток `_udp2`: все они делят одно соединение.
pub type H2SendRequest = SendRequest<Bytes>;

/// Установленное соединение HTTP/2.
pub struct Http2Transport {
    /// Отправитель запросов. Клонируется на каждый вызов.
    pub send_request: H2SendRequest,
    /// Задача, качающая кадры соединения.
    ///
    /// `h2` не продвигает соединение сам по себе — без опроса `Connection`
    /// оно не увидит ни исходящих, ни входящих кадров. Останавливается явно
    /// в [`Http2Transport::shutdown`]: падение `JoinHandle` саму задачу не
    /// останавливает.
    driver: JoinHandle<()>,
}

impl Http2Transport {
    /// Останавливает задачу, качающую соединение, и вместе с ней — само
    /// соединение: она единственная держит TLS-поток.
    pub fn shutdown(&self) {
        self.driver.abort();
    }
}

/// Поднимает TLS и рукопожатие HTTP/2 с сервером.
pub async fn connect(
    config: &TrustTunnelConfig,
    dialer: &dyn Dialer,
    host: &Address,
    port: u16,
) -> TrustTunnelResult<Http2Transport> {
    let tcp = dial::dial(dialer, host, port)
        .await
        .map_err(|e| TrustTunnelError::disconnected(e.to_string()))?;

    // ALPN `h2` обязателен (`PROTOCOL.md`, §3.1): сервер демультиплексирует
    // TLS по ALPN, и без него не поймёт, что за протокол ждать дальше.
    let tls = TlsClient::new(&config.tls, host, &[ALPN_H2])?;
    let io = tls.connect(tcp).await?;

    // Срок нужен отдельно от TLS: сервер, принявший TLS-соединение и
    // замолчавший до `SETTINGS`, не отличим от рабочего иначе — у своего
    // рукопожатия здесь протокол просто нет (`AGENTS.md`, чек-лист
    // приёмки: «у рукопожатия есть срок»).
    let (send_request, connection) = deadline::handshake("рукопожатие HTTP/2", async {
        h2::client::Builder::new()
            .initial_window_size(INITIAL_WINDOW_SIZE)
            .handshake(io)
            .await
            .map_err(|e| TrustTunnelError::transport(format!("рукопожатие HTTP/2: {e}")))
    })
    .await?;

    let driver = tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::debug!(%err, "соединение HTTP/2 с сервером trusttunnel завершено");
        }
    });

    Ok(Http2Transport {
        send_request,
        driver,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::duplex;

    use super::*;

    #[tokio::test]
    async fn shutdown_stops_the_driver_task() {
        // Настоящего сервера здесь нет: важно только то, что задача не
        // крутится вечно после `shutdown`, а не то, что отвечает пир.
        let (client_io, _server_io) = duplex(4096);
        let (send_request, connection) = h2::client::Builder::new()
            .initial_window_size(INITIAL_WINDOW_SIZE)
            .handshake(client_io)
            .await
            .expect("рукопожатие");

        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let transport = Http2Transport {
            send_request,
            driver,
        };

        transport.shutdown();

        let Http2Transport { driver, .. } = transport;
        let result = tokio::time::timeout(Duration::from_secs(1), driver).await;
        let joined = result.expect("задача обязана остановиться, а не крутиться вечно");
        assert!(
            joined.expect_err("остановлена через abort").is_cancelled(),
            "задача должна быть именно отменена, а не завершиться сама"
        );
    }
}
