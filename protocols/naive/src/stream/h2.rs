//! Двунаправленный поток `CONNECT` поверх HTTP/2.
//!
//! `h2` уже разделяет запрос и ответ на `SendStream`/`RecvStream` и даёт им
//! поллинговый API — в отличие от `h3` (см. [`super::h3`]), здесь не нужно
//! оборачивать асинхронные методы в отдельную задачу: `poll_capacity` и
//! `poll_data` ложатся на `AsyncWrite`/`AsyncRead` напрямую.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::to_io_error;

/// Поток `CONNECT`, установленный поверх HTTP/2.
pub struct H2Stream {
    send: SendStream<Bytes>,
    recv: RecvStream,
    /// Кусок последнего полученного кадра `DATA`, ещё не отданный читателю:
    /// кадр обычно больше, чем просит вызывающий `poll_read`.
    leftover: Bytes,
}

impl H2Stream {
    /// Собирает поток вокруг уже разделённых половин ответа на `CONNECT`.
    pub fn new(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            leftover: Bytes::new(),
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

            match Pin::new(&mut this.recv).poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    let len = data.len();
                    // Возвращаем окно приёма сразу: без этого сервер решит,
                    // что мы не успеваем читать, и перестанет слать данные —
                    // хотя мы их уже забрали.
                    if let Err(err) = this.recv.flow_control().release_capacity(len) {
                        return Poll::Ready(Err(to_io_error(err)));
                    }
                    this.leftover = data;
                }
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(to_io_error(err))),
                // Конец потока: сервер закрыл его штатно.
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
                // Поток закрыт с той стороны — писать больше некуда.
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
        // `h2` отправляет кадры `DATA` сразу же при `send_data` — отдельного
        // буфера на этом уровне нет, и ждать нечего.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Пустой кадр `DATA` с `END_STREAM` — аналог `FIN` в TCP: сообщает
        // серверу, что писать мы больше не будем, не обрывая чтение.
        self.get_mut()
            .send
            .send_data(Bytes::new(), true)
            .map_err(to_io_error)?;
        Poll::Ready(Ok(()))
    }
}
