//! Соединение HTTP/2 до сервера: TCP, TLS, рукопожатие `h2`.

use bytes::Bytes;
use h2::client::SendRequest;
use penguin_core::address::Address;
use penguin_proto::connect as dial;
use penguin_proto::dialer::Dialer;
use penguin_transport::tls::{ALPN_H2, TlsClient};
use tokio::task::JoinHandle;

use crate::config::NaiveConfig;
use crate::error::{NaiveError, NaiveResult};

/// Отправитель запросов HTTP/2.
///
/// Клонируется — им и открывается несколько потоков `CONNECT` на одном
/// соединении: `multiplex: true` в возможностях направления означает именно
/// это (`AGENTS.md`, договор [`penguin_proto::capabilities::Capabilities`]).
pub type H2SendRequest = SendRequest<Bytes>;

/// Установленное соединение HTTP/2.
pub struct Http2Transport {
    /// Отправитель запросов. Клонируется на каждый вызов `connect_tcp`.
    pub send_request: H2SendRequest,
    /// Задача, качающая кадры соединения.
    ///
    /// `h2` не продвигает соединение сам по себе — без опроса `Connection`
    /// оно не увидит ни исходящих, ни входящих кадров. Держится живой ровно
    /// столько же, сколько сам `Http2Transport`, и обязана быть остановлена
    /// явно в [`Http2Transport::shutdown`] — простое падение значения
    /// `JoinHandle` задачу не останавливает, она продолжает крутиться
    /// отдельно от всего, что на неё ссылалось.
    driver: JoinHandle<()>,
}

impl Http2Transport {
    /// Останавливает задачу, качающую соединение, и вместе с ней — само
    /// соединение: она единственная держит TLS-поток, и без неё сокет
    /// закрывается сам.
    ///
    /// У `h2` нет отдельного «закрой всё» без объекта `Connection`, а мы его
    /// не храним — он нужен только этой задаче. Обрыв через `abort` здесь
    /// настолько же корректен, насколько был бы явный `shutdown` сокета: то,
    /// что не отправилось, всё равно не должно было отправиться после того,
    /// как направление закрыто.
    pub fn shutdown(&self) {
        self.driver.abort();
    }
}

/// Поднимает TLS и рукопожатие HTTP/2 с сервером.
pub async fn connect(
    config: &NaiveConfig,
    dialer: &dyn Dialer,
    host: &Address,
    port: u16,
) -> NaiveResult<Http2Transport> {
    let tcp = dial::dial(dialer, host, port)
        .await
        .map_err(|e| NaiveError::Disconnected(e.to_string()))?;

    // ALPN `h2` обязателен: сервер понимает, что за протокол ждать в TLS,
    // только по нему, — а маскировка держится ровно на том, что снаружи это
    // неотличимо от обычного браузера, договорившегося на HTTP/2.
    let tls = TlsClient::new(&config.tls, host, &[ALPN_H2])?;
    let io = tls.connect(tcp).await?;

    let (send_request, connection) = h2::client::handshake(io)
        .await
        .map_err(|e| NaiveError::transport(format!("рукопожатие HTTP/2: {e}")))?;

    let driver = tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::debug!(%err, "соединение HTTP/2 с сервером naive завершено");
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
        let (send_request, connection) =
            h2::client::handshake(client_io).await.expect("рукопожатие");

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
