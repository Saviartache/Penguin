//! Поток `stream-one`: тело запроса туда, тело ответа обратно.
//!
//! Писать можно сразу; ответ ждёт первое чтение (как Xray `OpenStream`).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::h3::{H3Result, RecvStream, RequestStream, Response, SendStream};

type Waiting = Pin<Box<dyn Future<Output = (RecvStream, H3Result<Response>)> + Send>>;

/// Приём: ответ ещё в пути или уже идёт тело.
enum Recv {
    Waiting(Waiting),
    Body(RecvStream),
}

/// Поток XHTTP `stream-one` поверх HTTP/3.
pub struct XhttpStream {
    send: SendStream,
    recv: Recv,
}

impl XhttpStream {
    pub(super) fn new(stream: RequestStream) -> Self {
        let (send, mut recv) = stream.split();
        let waiting: Waiting = Box::pin(async move {
            let response = recv.response().await;
            (recv, response)
        });
        Self {
            send,
            recv: Recv::Waiting(waiting),
        }
    }

    fn poll_body(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<&mut RecvStream>> {
        if let Recv::Waiting(waiting) = &mut self.recv {
            let (recv, response) = ready!(waiting.as_mut().poll(cx));
            let status = response?.status();
            if status != 200 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("сервер XHTTP ответил {status}"),
                )));
            }
            self.recv = Recv::Body(recv);
        }
        match &mut self.recv {
            Recv::Body(body) => Poll::Ready(Ok(body)),
            Recv::Waiting(_) => Poll::Pending,
        }
    }
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let body = ready!(self.get_mut().poll_body(cx))?;
        Pin::new(body).poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpStream {
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
