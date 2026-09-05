//! Двунаправленный поток `CONNECT` поверх HTTP/3.
//!
//! У `h3` (в отличие от `h2`, см. [`super::h2`]) нет поллингового API на
//! запись: `RequestStream::send_data` — это `async fn`, а не `poll_*`.
//! Мостом служит стандартный приём — асинхронный вызов заворачивается в
//! `Pin<Box<dyn Future>>`, который живёт между вызовами `poll_write` ровно
//! до своего завершения, а поток записи возвращается обратно во владение
//! структуры, когда операция готова.
//!
//! Чтение проще: `poll_recv_data` в `h3` уже поллинговый, и оборачивать
//! асинхронщину незачем.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use h3::client::RequestStream;
use h3::quic::{RecvStream as QuicRecvStream, SendStream as QuicSendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::to_io_error;

/// Операция записи в процессе: поток заявки временно занят её будущим и
/// вернётся во владение [`H3Stream`], когда она завершится.
type PendingWrite<S> =
    Pin<Box<dyn Future<Output = (RequestStream<S, Bytes>, io::Result<()>)> + Send>>;

/// Поток `CONNECT`, установленный поверх HTTP/3.
///
/// `S` и `R` — половины двунаправленного потока `quic`-транспорта после
/// [`h3::client::RequestStream::split`]; для `h3-quinn` это его собственные
/// обёртки над `quinn::SendStream`/`quinn::RecvStream`.
pub struct H3Stream<S, R>
where
    S: QuicSendStream<Bytes> + Send + 'static,
    R: QuicRecvStream + Send + 'static,
{
    /// Свободен, пока не идёт запись; во время неё временно пуст — поток
    /// заявки живёт внутри [`Self::pending`] и вернётся сюда по готовности.
    send: Option<RequestStream<S, Bytes>>,
    pending: Option<PendingWrite<S>>,
    /// Сколько байт исходного `buf` относится к операции в [`Self::pending`]
    /// — ровно столько нужно вернуть из `poll_write`, когда она завершится.
    pending_len: usize,

    recv: RequestStream<R, Bytes>,
    /// Кусок последнего полученного кадра, ещё не отданный читателю.
    leftover: Bytes,
}

impl<S, R> H3Stream<S, R>
where
    S: QuicSendStream<Bytes> + Send + 'static,
    R: QuicRecvStream + Send + 'static,
{
    /// Собирает поток вокруг половин, уже разделённых [`RequestStream::split`].
    pub fn new(send: RequestStream<S, Bytes>, recv: RequestStream<R, Bytes>) -> Self {
        Self {
            send: Some(send),
            pending: None,
            pending_len: 0,
            recv,
            leftover: Bytes::new(),
        }
    }
}

impl<S, R> AsyncRead for H3Stream<S, R>
where
    S: QuicSendStream<Bytes> + Send + 'static,
    R: QuicRecvStream + Send + 'static,
{
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

            match this.recv.poll_recv_data(cx) {
                Poll::Ready(Ok(Some(mut data))) => {
                    let remaining = data.remaining();
                    this.leftover = data.copy_to_bytes(remaining);
                }
                // Конец потока: сервер закрыл его штатно.
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(to_io_error(err))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S, R> AsyncWrite for H3Stream<S, R>
where
    S: QuicSendStream<Bytes> + Send + 'static,
    R: QuicRecvStream + Send + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.pending.is_none() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let Some(mut send) = this.send.take() else {
                // Недостижимо при обычном использовании: `AsyncWrite` не
                // зовут повторно, пока прошлый вызов не вернул `Ready`, а
                // `send` всегда возвращается на место либо сюда, либо в
                // `pending` — иначе восстановить состояние честной ошибкой,
                // а не паникой (`AGENTS.md`, правило 4.3).
                return Poll::Ready(Err(io::Error::other(
                    "поток HTTP/3 занят предыдущей записью",
                )));
            };
            let chunk = Bytes::copy_from_slice(buf);
            this.pending_len = buf.len();
            this.pending = Some(Box::pin(async move {
                let result = send.send_data(chunk).await.map_err(to_io_error);
                (send, result)
            }));
        }

        // `pending` только что установлен, если был пуст, — обращение ниже
        // всегда находит будущее.
        let Some(future) = this.pending.as_mut() else {
            return Poll::Ready(Err(io::Error::other("операция записи потеряна")));
        };
        let (send, result) = ready!(future.as_mut().poll(cx));
        this.send = Some(send);
        this.pending = None;
        result?;
        Poll::Ready(Ok(this.pending_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(future) = this.pending.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let (send, result) = ready!(future.as_mut().poll(cx));
        this.send = Some(send);
        this.pending = None;
        Poll::Ready(result)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Незавершённая запись обязана закончиться раньше, чем поток
        // закроется, — иначе последние байты приложения потерялись бы.
        if let Some(future) = this.pending.as_mut() {
            let (send, result) = ready!(future.as_mut().poll(cx));
            this.send = Some(send);
            this.pending = None;
            result?;
        }

        let Some(mut send) = this.send.take() else {
            return Poll::Ready(Ok(()));
        };
        this.pending = Some(Box::pin(async move {
            let result = send.finish().await.map_err(to_io_error);
            (send, result)
        }));

        let Some(future) = this.pending.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let (send, result) = ready!(future.as_mut().poll(cx));
        this.send = Some(send);
        this.pending = None;
        Poll::Ready(result)
    }
}
