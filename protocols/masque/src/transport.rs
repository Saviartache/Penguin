//! Соединение HTTP/3 до прокси: QUIC поверх сокета от `Dialer` и рукопожатие `h3`.
//!
//! Устроено как у `naive` (`protocols/naive/src/transport/h3.rs`) и по той же
//! причине: сокет берётся у [`Dialer::bind_udp`], а не открывается здесь
//! напрямую — иначе рукопожатие ушло бы в собственный, ещё не поднятый
//! тоннель.
//!
//! # Что не проверяется — и почему
//!
//! RFC 9298, §3.4 требует, чтобы прокси подтвердил расширенный CONNECT
//! (`SETTINGS_ENABLE_CONNECT_PROTOCOL`, RFC 9220) прежде, чем клиент пошлёт
//! запрос с `:protocol: connect-udp`. Проверить это заранее не получится
//! стабильным способом: `h3` версии `0.0.8` даёт прочитать настройки собеседника
//! (`ConnectionState::settings`) только под фичой
//! `i-implement-a-third-party-backend-and-opt-into-breaking-changes` — она
//! для тех, кто пишет свой QUIC-бэкенд вместо `h3-quinn`, а не для того,
//! чтобы обычный протокол подглядывал за согласованием. Включать её ради
//! одной проверки значило бы держать в зависимостях интерфейс, который сам
//! `h3` не считает частью своего публичного контракта, — с любым патчем он
//! может измениться без предупреждения через semver.
//!
//! Поэтому этот клиент не ждёт и не проверяет — [`connect`] сразу собирает
//! [`Http3Transport`], а расширенный CONNECT либо срабатывает при первом
//! запросе (см. [`crate::session::Session::open_flow`]), либо нет. Если
//! прокси не подтвердил его, RFC 9220 относит это к нарушению протокола со
//! стороны клиента — сервер вправе ответить отказом на сам поток или закрыть
//! всё соединение целиком; и то и другое всплывает как обычная ошибка
//! [`crate::error::MasqueError::Disconnected`] или
//! [`crate::error::MasqueError::Refused`] на первой же попытке открыть
//! канал, а не как отдельная, заранее пойманная причина.
//!
//! `h3` также умеет объявить `SETTINGS_H3_DATAGRAM` (RFC 9297, §2.1.1;
//! `Builder::enable_datagram`) — этот клиент её не объявляет вовсе, и
//! причина здесь не та же: подробности в документации [`crate::flow`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use penguin_proto::dialer::Dialer;
use penguin_transport::tls::{ALPN_H3, client_config as tls_client_config};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, EndpointConfig};
use tokio::task::JoinHandle;

use crate::config::MasqueConfig;
use crate::error::{MasqueError, MasqueResult};

/// Отправитель запросов HTTP/3 — конкретный, а не обобщённый по транспорту:
/// в этом крейте он всегда один, поверх `h3-quinn`.
pub type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// Двунаправленный поток `h3` до разделения на половины [`h3::client::RequestStream::split`].
pub type H3BidiStream = h3_quinn::BidiStream<Bytes>;

/// Половина потока на отправку — после разделения.
pub type H3SendHalf = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;

/// Половина потока на приём — после разделения.
pub type H3RecvHalf = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

/// Установленное соединение HTTP/3 с прокси MASQUE.
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
    _driver: JoinHandle<()>,
}

/// Поднимает QUIC и рукопожатие HTTP/3 с прокси.
pub async fn connect(
    config: &MasqueConfig,
    dialer: &dyn Dialer,
    server: SocketAddr,
    server_name: &str,
) -> MasqueResult<Http3Transport> {
    // Локальный адрес того же семейства, что и удалённый: сокет IPv4 до
    // прокси IPv6 не достучится.
    let local = match server.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let udp = dialer
        .bind_udp(local)
        .await
        .map_err(|e| MasqueError::Disconnected(e.to_string()))?
        .into_std()
        .map_err(|e| MasqueError::Disconnected(e.to_string()))?;

    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        None,
        udp,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| MasqueError::transport(format!("не удалось создать эндпойнт QUIC: {e}")))?;

    let connection = endpoint
        .connect_with(client_config(config)?, server, server_name)
        .map_err(|e| MasqueError::transport(format!("не удалось начать подключение: {e}")))?
        .await
        .map_err(|e| MasqueError::transport(format!("рукопожатие QUIC не завершилось: {e}")))?;

    // `enable_datagram` намеренно не включается — см. документацию модуля
    // [`crate::flow`].
    let (mut h3_driver, send_request) = h3::client::builder()
        .enable_extended_connect(true)
        .build(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|e| MasqueError::transport(format!("рукопожатие HTTP/3: {e}")))?;

    let driver = tokio::spawn(async move {
        let err = std::future::poll_fn(|cx| h3_driver.poll_close(cx)).await;
        tracing::debug!(%err, "соединение HTTP/3 с прокси MASQUE завершено");
    });

    Ok(Http3Transport {
        endpoint,
        connection,
        send_request,
        _driver: driver,
    })
}

/// Настройки клиента QUIC: TLS с ALPN `h3`.
fn client_config(config: &MasqueConfig) -> MasqueResult<ClientConfig> {
    let crypto = tls_client_config(&config.tls, &[ALPN_H3])?;
    let crypto = QuicClientConfig::try_from(crypto)
        .map_err(|e| MasqueError::config(format!("TLS не годится для QUIC: {e}")))?;
    Ok(ClientConfig::new(Arc::new(crypto)))
}
