//! Соединение с сервером по HTTP/2: TCP, TLS, рукопожатие `h2`.
//!
//! Сокет выдаёт [`Dialer`] (`AGENTS.md`, §3).

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

/// Начальное окно потока HTTP/2, как у Chrome (`PROTOCOL.md`, §3.1).
const INITIAL_WINDOW_SIZE: u32 = 131_072;

/// Отправитель запросов HTTP/2; клонируется, все потоки делят одно соединение.
pub type H2SendRequest = SendRequest<Bytes>;

/// Установленное соединение HTTP/2.
pub struct Http2Transport {
    /// Отправитель запросов. Клонируется на каждый вызов.
    pub send_request: H2SendRequest,
    /// Задача, качающая кадры; останавливается в [`Http2Transport::shutdown`].
    driver: JoinHandle<()>,
}

impl Http2Transport {
    /// Останавливает задачу, а с ней и соединение.
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

    let tls = TlsClient::new(&config.tls, host, &[ALPN_H2])?;
    let io = tls.connect(tcp).await?;

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
