//! Поток приложения: две половины `quinn` под одним
//! [`ProxyStream`](penguin_proto::stream::ProxyStream), плюс соединение,
//! чтобы эндпойнт пережил поток. `poll_shutdown` доводит запись до `finish`.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::link::Link;
use crate::pool;

/// Поток Juicity: две половины QUIC под одной крышей.
pub struct JuicityStream {
    _link: Arc<Link>,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl std::fmt::Debug for JuicityStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JuicityStream").finish()
    }
}

impl JuicityStream {
    /// Сводит половины вместе.
    pub fn new(stream: pool::Stream) -> Self {
        Self {
            _link: stream.link,
            send: stream.send,
            recv: stream.recv,
        }
    }
}

impl AsyncRead for JuicityStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for JuicityStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // У `SendStream` есть собственный `poll_write` с другой ошибкой.
        AsyncWrite::poll_write(Pin::new(&mut this.send), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        AsyncWrite::poll_flush(Pin::new(&mut this.send), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        AsyncWrite::poll_shutdown(Pin::new(&mut this.send), cx)
    }
}
