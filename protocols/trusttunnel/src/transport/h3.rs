//! Соединение с сервером по HTTP/3: QUIC через `Dialer` и HTTP/3 (`PROTOCOL.md`, §3.2).
//!
//! Срок простоя QUIC по спецификации (`connection_timeout` не определён)
//! заменён пробой живости QUIC и `_check`.

use penguin_core::address::Address;
use penguin_proto::dialer::Dialer;
use penguin_transport::h3;
use penguin_transport::quic::{self, QuicLink};
use penguin_transport::tls::ALPN_H3;

use crate::config::TrustTunnelConfig;
use crate::error::{TrustTunnelError, TrustTunnelResult};

/// Установленное соединение HTTP/3.
pub struct Http3Transport {
    /// Соединение QUIC — для закрытия.
    pub link: QuicLink,
    /// HTTP/3 поверх него.
    pub h3: h3::Connection,
}

/// Поднимает QUIC и HTTP/3 с сервером. ALPN `h3` обязателен (§3.2).
pub async fn connect(
    config: &TrustTunnelConfig,
    dialer: &dyn Dialer,
    host: &Address,
    port: u16,
) -> TrustTunnelResult<Http3Transport> {
    let server_name = config.server_name()?;
    let link = quic::connect(dialer, host, port, &server_name, &config.tls, &[ALPN_H3]).await?;
    let h3 = h3::Connection::new(link.connection.clone(), h3::Options::default())
        .await
        .map_err(|e| TrustTunnelError::transport(format!("HTTP/3 не поднялся: {e}")))?;
    Ok(Http3Transport { link, h3 })
}
