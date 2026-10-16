//! Соединение с сервером независимо от переноса: открыть поток `CONNECT`.

use penguin_proto::dialer::Dialer;
use penguin_proto::stream::ProxyStream;
use penguin_transport::TransportError;
use penguin_transport::h3::code::H3_NO_ERROR;

use super::h2::{self, Http2Transport};
use super::h3::{self, Http3Transport};
use crate::config::{Transport, TrustTunnelConfig};
use crate::connect;
use crate::error::{TrustTunnelError, TrustTunnelResult};
use penguin_transport::h2::H2Stream;

/// Поднятое соединение с сервером.
pub enum Link {
    /// HTTP/2 поверх TLS.
    Http2(Http2Transport),
    /// HTTP/3 поверх QUIC.
    Http3(Http3Transport),
}

impl Link {
    /// Поднимает соединение тем переносом, что выбран в настройках.
    pub async fn connect(
        config: &TrustTunnelConfig,
        dialer: &dyn Dialer,
    ) -> TrustTunnelResult<Self> {
        let (host, port) = config.endpoint()?;
        Ok(match config.transport {
            Transport::H2 => Self::Http2(h2::connect(config, dialer, &host, port).await?),
            Transport::H3 => Self::Http3(h3::connect(config, dialer, &host, port).await?),
        })
    }

    /// Отправляет `CONNECT` до `authority` и ждёт ответа. Возвращает код и
    /// поток тела. `end_stream` — тела у запроса не будет (`_check`).
    pub async fn open(
        &self,
        authority: &str,
        credentials: (&str, &str),
        end_stream: bool,
    ) -> TrustTunnelResult<(u16, Box<dyn ProxyStream>)> {
        match self {
            Self::Http2(transport) => open_h2(transport, authority, credentials, end_stream).await,
            Self::Http3(transport) => open_h3(transport, authority, credentials, end_stream).await,
        }
    }

    /// Закрывает соединение.
    pub async fn shutdown(&self) {
        match self {
            Self::Http2(transport) => transport.shutdown(),
            Self::Http3(transport) => transport.link.close(H3_NO_ERROR, b"").await,
        }
    }
}

async fn open_h2(
    transport: &Http2Transport,
    authority: &str,
    credentials: (&str, &str),
    end_stream: bool,
) -> TrustTunnelResult<(u16, Box<dyn ProxyStream>)> {
    let mut send_request = transport
        .send_request
        .clone()
        .ready()
        .await
        .map_err(|e| TrustTunnelError::disconnected(e.to_string()))?;
    let request = connect::request(authority, credentials)?;
    let (response, send_stream) = send_request
        .send_request(request, end_stream)
        .map_err(|e| TrustTunnelError::transport(format!("запрос CONNECT {authority}: {e}")))?;
    let response = response
        .await
        .map_err(|e| TrustTunnelError::disconnected(e.to_string()))?;
    let status = response.status().as_u16();
    let stream = H2Stream::new(send_stream, response.into_body());
    Ok((status, Box::new(stream)))
}

async fn open_h3(
    transport: &Http3Transport,
    authority: &str,
    credentials: (&str, &str),
    end_stream: bool,
) -> TrustTunnelResult<(u16, Box<dyn ProxyStream>)> {
    let request = connect::request_h3(authority, credentials);
    let mut stream = transport
        .h3
        .send_request(&request)
        .await
        .map_err(TransportError::from)?;
    if end_stream {
        stream.finish().map_err(TransportError::from)?;
    }
    let response = stream.response().await.map_err(TransportError::from)?;
    Ok((response.status(), Box::new(stream)))
}
