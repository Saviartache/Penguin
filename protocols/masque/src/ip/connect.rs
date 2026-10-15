//! Устанавливает транспорт `CONNECT-IP`: расширенный `CONNECT` поверх
//! HTTP/3. Дальше — поток капсул.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use penguin_core::address::SocketAddress;
use penguin_proto::dialer::Dialer;
use penguin_proto::stream::ProxyStream;
use penguin_transport::quic::{self, QuicLink};
use penguin_transport::tls::ALPN_H3;
use penguin_transport::{TransportError, deadline, h3};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::request;
use crate::config::MasqueConfig;
use crate::error::{MasqueError, MasqueResult};

/// Дозванивается до прокси и открывает поток капсул `CONNECT-IP`.
pub(super) async fn open(
    dialer: &dyn Dialer,
    config: &MasqueConfig,
) -> MasqueResult<Box<dyn ProxyStream>> {
    config.validate()?;
    let (host, port) = config.endpoint()?;
    let server_name = config.server_name()?;
    let authority = SocketAddress::new(host.clone(), port).to_wire();
    let link = quic::connect(dialer, &host, port, &server_name, &config.tls, &[ALPN_H3]).await?;
    // IP-пакеты идут капсулами по потоку: датаграммы не объявляются, и
    // сервер обязан говорить капсулами же (RFC 9297, §3.5).
    let connection = h3::Connection::new(link.connection.clone(), h3::Options::default())
        .await
        .map_err(|e| MasqueError::transport(format!("HTTP/3 не поднялся: {e}")))?;

    let request = request::request(&authority, config.authorization.as_deref());
    let stream = deadline::handshake("CONNECT-IP", async {
        let mut stream = connection
            .send_request(&request)
            .await
            .map_err(TransportError::from)?;
        let response = stream.response().await.map_err(TransportError::from)?;
        request::check_response(&response)?;
        Ok::<_, MasqueError>(stream)
    })
    .await?;

    Ok(Box::new(Tunnel {
        stream,
        _connection: connection,
        _link: link,
    }))
}

/// Поток `CONNECT-IP` вместе с соединением, которое его несёт: пока жив
/// поток, живо и оно.
struct Tunnel {
    stream: h3::RequestStream,
    _connection: h3::Connection,
    _link: QuicLink,
}

impl AsyncRead for Tunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
