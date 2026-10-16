//! Поток запроса HTTP/2 как `AsyncRead + AsyncWrite` (naive, TrustTunnel, gRPC).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use h2::client::ResponseFuture;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Приводит ошибку `h2` к языку `AsyncRead`/`AsyncWrite`.
fn to_io_error(err: h2::Error) -> io::Error {
    io::Error::other(err)
}

/// Поток запроса поверх HTTP/2.
pub struct H2Stream {
    send: SendStream<Bytes>,
    recv: Recv,
    /// Остаток последнего кадра `DATA`.
    leftover: Bytes,
}

/// Приём: ответ ещё не пришёл или уже идёт тело.
enum Recv {
    Waiting(ResponseFuture),
    Body(RecvStream),
}

impl H2Stream {
    /// Собирает поток вокруг отправки запроса и тела уже полученного ответа.
    pub fn new(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        Self {
            send,
            recv: Recv::Body(recv),
            leftover: Bytes::new(),
        }
    }

    /// Поток без ответа: писать можно сразу, ответ ждёт первое чтение (не `2xx` — ошибка).
    pub fn awaiting(send: SendStream<Bytes>, response: ResponseFuture) -> Self {
        Self {
            send,
            recv: Recv::Waiting(response),
            leftover: Bytes::new(),
        }
    }

    /// Тело ответа; ждёт сам ответ, если он ещё не пришёл.
    fn poll_body(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<&mut RecvStream>> {
        if let Recv::Waiting(response) = &mut self.recv {
            let response = ready!(Pin::new(response).poll(cx)).map_err(to_io_error)?;
            if !response.status().is_success() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("сервер ответил {}", response.status()),
                )));
            }
            self.recv = Recv::Body(response.into_body());
        }
        match &mut self.recv {
            Recv::Body(body) => Poll::Ready(Ok(body)),
            Recv::Waiting(_) => Poll::Pending,
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            if !this.leftover.is_empty() {
                let take = this.leftover.len().min(buf.remaining());
                buf.put_slice(&this.leftover[..take]);
                this.leftover.advance(take);
                return Poll::Ready(Ok(()));
            }

            let body = ready!(this.poll_body(cx))?;
            match Pin::new(&mut *body).poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    let len = data.len();
                    if let Err(err) = body.flow_control().release_capacity(len) {
                        return Poll::Ready(Err(to_io_error(err)));
                    }
                    this.leftover = data;
                }
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(to_io_error(err))),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if this.send.capacity() == 0 {
            this.send.reserve_capacity(buf.len());
            match this.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(_))) => {}
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(to_io_error(err))),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "поток HTTP/2 закрыт для записи",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        let take = this.send.capacity().min(buf.len());
        this.send
            .send_data(Bytes::copy_from_slice(&buf[..take]), false)
            .map_err(to_io_error)?;
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .send
            .send_data(Bytes::new(), true)
            .map_err(to_io_error)?;
        Poll::Ready(Ok(()))
    }
}
