//! Соединение HTTP/3 до прокси: QUIC через `Dialer` и HTTP/3 с датаграммами.
//!
//! Датаграммы (RFC 9297) объявляются всегда; расширенный `CONNECT` (RFC 9220)
//! проверяет сам HTTP/3.

use penguin_core::address::Address;
use penguin_proto::dialer::Dialer;
use penguin_transport::h3;
use penguin_transport::quic::{self, QuicLink};
use penguin_transport::tls::ALPN_H3;

use crate::config::MasqueConfig;
use crate::error::{MasqueError, MasqueResult};

/// Установленное соединение HTTP/3 с прокси MASQUE.
pub struct Http3Transport {
    /// Соединение QUIC — для закрытия.
    pub link: QuicLink,
    /// HTTP/3 поверх него.
    pub h3: h3::Connection,
}

/// Поднимает QUIC и HTTP/3 с прокси.
pub async fn connect(
    config: &MasqueConfig,
    dialer: &dyn Dialer,
    host: &Address,
    port: u16,
    server_name: &str,
) -> MasqueResult<Http3Transport> {
    let link = quic::connect(dialer, host, port, server_name, &config.tls, &[ALPN_H3]).await?;
    let options = h3::Options { datagrams: true };
    let h3 = h3::Connection::new(link.connection.clone(), options)
        .await
        .map_err(|e| MasqueError::transport(format!("HTTP/3 не поднялся: {e}")))?;
    Ok(Http3Transport { link, h3 })
}
