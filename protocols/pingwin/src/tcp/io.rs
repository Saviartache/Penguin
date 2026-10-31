//! Половины потока HTTP/2 как `AsyncWrite` и `AsyncRead`; запись ждёт окна, а не копит.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

fn to_io(err: h2::Error) -> io::Error {
    io::Error::other(err)
}

/// Ждёт окна для `want` байт; `Ok(n)` — сколько можно записать сейчас.
fn poll_window(
    send: &mut SendStream<Bytes>,
    cx: &mut Context<'_>,
    want: usize,
) -> Poll<io::Result<usize>> {
    loop {
        let ready = send.capacity();
        if ready > 0 {
            return Poll::Ready(Ok(ready.min(want)));
        }
        send.reserve_capacity(want);
        match ready!(send.poll_capacity(cx)) {
            Some(Ok(_)) => {}
            Some(Err(err)) => return Poll::Ready(Err(to_io(err))),
            None => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "поток HTTP/2 закрыт для записи",
                )));
            }
        }
    }
}

/// Отправляет `data` целиком, дожидаясь окна по частям.
pub async fn send_all(send: &mut SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
    while !data.is_empty() {
        let take = std::future::poll_fn(|cx| poll_window(send, cx, data.len())).await?;
        send.send_data(data.split_to(take), false).map_err(to_io)?;
    }
    Ok(())
}

/// Половина записи.
pub struct H2Send(pub(crate) SendStream<Bytes>);

impl AsyncWrite for H2Send {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let send = &mut self.get_mut().0;
        let take = ready!(poll_window(send, cx, buf.len()))?;
        send.send_data(Bytes::copy_from_slice(&buf[..take]), false)
            .map_err(to_io)?;
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .0
            .send_data(Bytes::new(), true)
            .map_err(to_io)?;
        Poll::Ready(Ok(()))
    }
}

/// Половина чтения; окно возвращается сразу, как кадр прочитан.
pub struct H2Recv {
    recv: RecvStream,
    /// Остаток последнего кадра `DATA`.
    leftover: Bytes,
}

impl H2Recv {
    /// Оборачивает тело запроса или ответа.
    pub fn new(recv: RecvStream) -> Self {
        Self {
            recv,
            leftover: Bytes::new(),
        }
    }

    /// Следующий кадр `DATA`; `None` — конец потока.
    pub async fn chunk(&mut self) -> io::Result<Option<Bytes>> {
        if !self.leftover.is_empty() {
            return Ok(Some(std::mem::take(&mut self.leftover)));
        }
        std::future::poll_fn(|cx| self.poll_chunk(cx)).await
    }

    fn poll_chunk(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        match ready!(self.recv.poll_data(cx)) {
            Some(Ok(data)) => {
                self.recv
                    .flow_control()
                    .release_capacity(data.len())
                    .map_err(to_io)?;
                Poll::Ready(Ok(Some(data)))
            }
            Some(Err(err)) => Poll::Ready(Err(to_io(err))),
            None => Poll::Ready(Ok(None)),
        }
    }
}

impl AsyncRead for H2Recv {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.leftover.is_empty() {
            match ready!(this.poll_chunk(cx))? {
                Some(data) => this.leftover = data,
                None => return Poll::Ready(Ok(())),
            }
        }
        let take = this.leftover.len().min(buf.remaining());
        buf.put_slice(&this.leftover[..take]);
        this.leftover.advance(take);
        Poll::Ready(Ok(()))
    }
}
