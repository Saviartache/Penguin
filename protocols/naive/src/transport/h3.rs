//! Соединение HTTP/3 до сервера: QUIC поверх сокета от `Dialer`, рукопожатие `h3`.
//!
//! Устроено так же, как у TUIC и Hysteria 2, и по той же причине: сокет
//! берётся у [`Dialer::bind_udp`], а не открывается здесь напрямую. TUN
//! перехватывает весь трафик машины, и сокет, открытый обычным способом,
//! отправил бы пакеты в собственный, ещё не поднятый тоннель.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use h3::client::SendRequest;
use penguin_proto::dialer::Dialer;
use penguin_transport::tls::client_config as tls_client_config;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, EndpointConfig};
use tokio::task::JoinHandle;

use crate::config::NaiveConfig;
use crate::error::{NaiveError, NaiveResult};

/// Отправитель запросов HTTP/3.
///
/// Клонируется по той же причине, что и у HTTP/2 (см. [`super::h2`]):
/// несколько потоков `CONNECT` делят одно соединение QUIC.
pub type H3SendRequest = SendRequest<h3_quinn::OpenStreams, Bytes>;

/// Установленное соединение HTTP/3.
pub struct Http3Transport {
    /// Эндпойнт. Хранится рядом не для красоты: он владеет задачей
    /// ввода-вывода, и как только последняя ссылка на него исчезает,
    /// соединение умирает вместе с ней.
    pub endpoint: Endpoint,
    /// Соединение QUIC — нужно снаружи для срока жизни и диагностики.
    pub connection: quinn::Connection,
    /// Отправитель запросов HTTP/3.
    pub send_request: H3SendRequest,
    /// Задача, качающая служебные потоки HTTP/3.
    ///
    /// Без неё `h3` сочтёт соединение сломанным: он не продвигает себя сам,
    /// а ждёт, что кто-то опрашивает `Connection::poll_close`.
    _driver: JoinHandle<()>,
}

/// Поднимает QUIC и рукопожатие HTTP/3 с сервером.
pub async fn connect(
    config: &NaiveConfig,
    dialer: &dyn Dialer,
    server: SocketAddr,
    server_name: &str,
) -> NaiveResult<Http3Transport> {
    // Локальный адрес того же семейства, что и удалённый: сокет IPv4 до
    // сервера IPv6 не достучится.
    let local = match server.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let udp = dialer
        .bind_udp(local)
        .await
        .map_err(|e| NaiveError::Disconnected(e.to_string()))?
        .into_std()
        .map_err(|e| NaiveError::Disconnected(e.to_string()))?;

    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        None,
        udp,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| NaiveError::transport(format!("не удалось создать эндпойнт QUIC: {e}")))?;

    let connection = endpoint
        .connect_with(client_config(config)?, server, server_name)
        .map_err(|e| NaiveError::transport(format!("не удалось начать подключение: {e}")))?
        .await
        .map_err(|e| NaiveError::transport(format!("рукопожатие QUIC не завершилось: {e}")))?;

    let (mut h3_driver, send_request) =
        h3::client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(|e| NaiveError::transport(format!("рукопожатие HTTP/3: {e}")))?;

    let driver = tokio::spawn(async move {
        let err = std::future::poll_fn(|cx| h3_driver.poll_close(cx)).await;
        tracing::debug!(%err, "соединение HTTP/3 с сервером naive завершено");
    });

    Ok(Http3Transport {
        endpoint,
        connection,
        send_request,
        _driver: driver,
    })
}

/// Настройки клиента QUIC: TLS с ALPN `h3`.
fn client_config(config: &NaiveConfig) -> NaiveResult<ClientConfig> {
    let crypto = tls_client_config(&config.tls, &[penguin_transport::tls::ALPN_H3])?;
    let crypto = QuicClientConfig::try_from(crypto)
        .map_err(|e| NaiveError::config(format!("TLS не годится для QUIC: {e}")))?;
    Ok(ClientConfig::new(Arc::new(crypto)))
}
