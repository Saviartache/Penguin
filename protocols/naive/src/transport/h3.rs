//! Соединение HTTP/3 до сервера: QUIC поверх сокета от `Dialer` и HTTP/3.

use penguin_proto::dialer::Dialer;
use penguin_transport::h3;
use penguin_transport::quic::{self, QuicLink};
use penguin_transport::tls::ALPN_H3;

use crate::config::NaiveConfig;
use crate::error::{NaiveError, NaiveResult};

/// Установленное соединение HTTP/3.
pub struct Http3Transport {
    /// Соединение QUIC — для закрытия.
    pub link: QuicLink,
    /// HTTP/3 поверх него. Клонируется на каждый поток `CONNECT`.
    pub h3: h3::Connection,
}

/// Поднимает QUIC и HTTP/3 с сервером.
pub async fn connect(config: &NaiveConfig, dialer: &dyn Dialer) -> NaiveResult<Http3Transport> {
    let (host, port) = config.endpoint()?;
    let server_name = config.server_name()?;
    let link = quic::connect(dialer, &host, port, &server_name, &config.tls, &[ALPN_H3]).await?;
    let h3 = h3::Connection::new(link.connection.clone(), h3::Options::default())
        .await
        .map_err(|e| NaiveError::transport(format!("HTTP/3 не поднялся: {e}")))?;
    Ok(Http3Transport { link, h3 })
}
