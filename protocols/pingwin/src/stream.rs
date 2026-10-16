//! Поток `CONNECT`: писать можно сразу, ответ ждёт первое чтение (отказ - его ошибка).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use penguin_transport::h3::{RecvStream, RequestStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::error::{PingwinError, PingwinResult};

/// Сколько тела отказа читать как причину.
const MAX_REASON: u64 = 1024;

type Waiting = Pin<Box<dyn Future<Output = (RecvStream, PingwinResult<()>)> + Send>>;

/// Приём: ответ в пути, тело или отказ.
enum Recv {
    Waiting(Waiting),
    Body(RecvStream),
    Failed(io::ErrorKind, String),
}

/// Поток до цели через сервер Pingwin.
pub struct PingwinStream {
    send: SendStream,
    recv: Recv,
}

impl std::fmt::Debug for PingwinStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PingwinStream")
            .field("id", &self.send.id())
            .finish()
    }
}

impl PingwinStream {
    pub(crate) fn new(stream: RequestStream, target: String) -> Self {
        let (send, mut recv) = stream.split();
        let waiting: Waiting = Box::pin(async move {
            let confirmed = confirm(&mut recv, target).await;
            (recv, confirmed)
        });
        Self {
            send,
            recv: Recv::Waiting(waiting),
        }
    }

    fn poll_body(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<&mut RecvStream>> {
        if let Recv::Waiting(waiting) = &mut self.recv {
            let (recv, confirmed) = ready!(waiting.as_mut().poll(cx));
            self.recv = match confirmed {
                Ok(()) => Recv::Body(recv),
                Err(err) => {
                    let err = io::Error::from(err);
                    Recv::Failed(err.kind(), err.to_string())
                }
            };
        }
        match &mut self.recv {
            Recv::Body(body) => Poll::Ready(Ok(body)),
            Recv::Failed(kind, reason) => Poll::Ready(Err(io::Error::new(*kind, reason.clone()))),
            Recv::Waiting(_) => Poll::Pending,
        }
    }
}

/// Ждёт ответ; не `2xx` — отказ с причиной из тела.
async fn confirm(recv: &mut RecvStream, target: String) -> PingwinResult<()> {
    let status = recv.response().await?.status();
    if (200..300).contains(&status) {
        return Ok(());
    }
    let mut body = Vec::new();
    if let Err(err) = (&mut *recv).take(MAX_REASON).read_to_end(&mut body).await {
        tracing::debug!(%err, "причина отказа не дочиталась");
    }
    let reason = String::from_utf8_lossy(&body).trim().to_owned();
    Err(PingwinError::Refused {
        target,
        reason: if reason.is_empty() {
            format!("ответ {status}")
        } else {
            reason
        },
    })
}

impl AsyncRead for PingwinStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let body = ready!(self.get_mut().poll_body(cx))?;
        Pin::new(body).poll_read(cx, buf)
    }
}

impl AsyncWrite for PingwinStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().send).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}
