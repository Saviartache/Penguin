//! Соединение QUIC поверх сокета от [`Dialer::bind_udp`] (мимо собственного тоннеля).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use penguin_core::address::Address;
use penguin_proto::dialer::Dialer;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, EndpointConfig, TransportConfig};

use crate::deadline;
use crate::error::{TransportError, TransportResult};
use crate::tls::{TlsConfig, client_config};

/// Проба живости: NAT забывает простаивающее соединение раньше тайм-аута quinn.
const KEEP_ALIVE: Duration = Duration::from_secs(10);

/// Поднятое соединение QUIC.
#[derive(Debug)]
pub struct QuicLink {
    /// Эндпойнт; без него соединение мертво.
    pub endpoint: Endpoint,
    /// Соединение.
    pub connection: quinn::Connection,
}

impl QuicLink {
    /// Соединение ещё не закрыто ни одной из сторон.
    pub fn is_alive(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    /// Закрывает соединение и ждёт отправки прощального пакета.
    pub async fn close(&self, code: u64, reason: &[u8]) {
        let code = quinn::VarInt::from_u64(code).unwrap_or(quinn::VarInt::MAX);
        self.connection.close(code, reason);
        self.endpoint.wait_idle().await;
    }
}

/// Разрешает адрес сервера мимо тоннеля и поднимает QUIC с ALPN `alpn`.
pub async fn connect(
    dialer: &dyn Dialer,
    host: &Address,
    port: u16,
    server_name: &str,
    tls: &TlsConfig,
    alpn: &[&[u8]],
) -> TransportResult<QuicLink> {
    let server = resolve(dialer, host, port).await?;
    let endpoint = endpoint(dialer, server).await?;
    let connecting = endpoint
        .connect_with(quic_config(tls, alpn)?, server, server_name)
        .map_err(|e| TransportError::config(format!("подключение QUIC не начато: {e}")))?;
    let connection = deadline::handshake("рукопожатие QUIC", async {
        connecting
            .await
            .map_err(|e| TransportError::disconnected(format!("рукопожатие QUIC: {e}")))
    })
    .await?;
    Ok(QuicLink {
        endpoint,
        connection,
    })
}

/// Первый адрес сервера через `Dialer`.
async fn resolve(dialer: &dyn Dialer, host: &Address, port: u16) -> TransportResult<SocketAddr> {
    penguin_proto::connect::resolve(dialer, host, port)
        .await
        .map_err(|e| TransportError::disconnected(e.to_string()))?
        .into_iter()
        .next()
        .ok_or_else(|| TransportError::disconnected(format!("`{host}` не разрешился")))
}

/// Эндпойнт над сокетом от `Dialer`, того же семейства, что и сервер.
async fn endpoint(dialer: &dyn Dialer, server: SocketAddr) -> TransportResult<Endpoint> {
    let local = match server.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = dialer
        .bind_udp(local)
        .await
        .map_err(|e| TransportError::disconnected(e.to_string()))?
        .into_std()?;
    Ok(Endpoint::new(
        EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?)
}

fn quic_config(tls: &TlsConfig, alpn: &[&[u8]]) -> TransportResult<ClientConfig> {
    let crypto = QuicClientConfig::try_from(client_config(tls, alpn)?)
        .map_err(|e| TransportError::config(format!("TLS не годится для QUIC: {e}")))?;
    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE));
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport));
    Ok(config)
}
