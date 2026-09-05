//! Поток приложения — одна сессия Mieru внутри неявного соединения.
//!
//! Снаружи это обычный [`ProxyStream`](penguin_proto::stream::ProxyStream).
//! Читают из очереди, которую наполняет задача чтения `underlay`; пишут
//! сегментами данных через общий замок соединения — тот же приём, что у
//! AnyTLS (`protocols/anytls/src/stream.rs`), и по той же причине: замок
//! асинхронный, а `poll_write` синхронный, поэтому отправка живёт отложенной
//! задачей внутри потока.
//!
//! # Закрытие
//!
//! `poll_shutdown` не шлёт `closeSessionRequest`: как и у AnyTLS, закрытие
//! сессии Mieru рвёт её целиком, в обе стороны, а не только на запись, — и
//! приложение, ждущее ответа после «я всё сказал», его бы не дождалось.
//! Просьба закрыть сессию уходит в `Drop`, когда ответ уже никому не нужен.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::segment;
use crate::underlay::{Msg, SessionState, Underlay};

/// Отложенная отправка сегмента.
type Sending = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

/// Поток Mieru.
pub struct MieruStream {
    underlay: Arc<Underlay>,
    id: u32,
    state: Arc<SessionState>,
    /// Что пришло из underlay.
    incoming: mpsc::Receiver<Msg>,
    /// Прочитанное, но не отданное приложению.
    leftover: Bytes,
    /// Собеседник закончил.
    finished: bool,
    /// Сегмент, который сейчас отправляется, и сколько байт он унёс.
    sending: Option<(Sending, usize)>,
}

impl std::fmt::Debug for MieruStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MieruStream")
            .field("underlay", &self.underlay.seq())
            .field("id", &self.id)
            .finish()
    }
}

impl MieruStream {
    /// Собирает поток. Зовёт его только [`Underlay::open_session`].
    pub(crate) fn new(
        underlay: Arc<Underlay>,
        id: u32,
        state: Arc<SessionState>,
        incoming: mpsc::Receiver<Msg>,
    ) -> Self {
        Self {
            underlay,
            id,
            state,
            incoming,
            leftover: Bytes::new(),
            finished: false,
            sending: None,
        }
    }

    /// Номер сессии в соединении.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Доводит начатую отправку до конца.
    fn poll_sending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let Some((sending, len)) = self.sending.as_mut() else {
            return Poll::Ready(Ok(0));
        };
        let len = *len;
        match sending.as_mut().poll(cx) {
            Poll::Ready(done) => {
                self.sending = None;
                Poll::Ready(done.map(|()| len))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Отдаёт приложению кусок отложенного.
    fn take_leftover(&mut self, buf: &mut ReadBuf<'_>) {
        let take = self.leftover.len().min(buf.remaining());
        buf.put_slice(&self.leftover[..take]);
        self.leftover = self.leftover.slice(take..);
    }
}

impl AsyncRead for MieruStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.leftover.is_empty() {
                this.take_leftover(buf);
                return Poll::Ready(Ok(()));
            }
            if this.finished {
                return Poll::Ready(Ok(()));
            }

            match this.incoming.poll_recv(cx) {
                Poll::Ready(Some(Msg::Data(data))) => this.leftover = data,
                Poll::Ready(Some(Msg::Eof)) => {
                    this.finished = true;
                    return Poll::Ready(Ok(()));
                }
                // Очередь закрылась без прощания: либо сессию сняли, либо
                // умерло всё соединение. Первое — конец, второе — обрыв, и
                // путать их значит показывать обрыв успехом.
                Poll::Ready(None) => {
                    this.finished = true;
                    return Poll::Ready(match this.underlay.death() {
                        Some(reason) => Err(io::Error::other(reason)),
                        None => Ok(()),
                    });
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for MieruStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Начатую отправку надо довести: байты для неё уже скопированы, и
        // бросить её значит потерять их посреди потока.
        if this.sending.is_some() {
            return this.poll_sending(cx);
        }
        if let Some(reason) = this.underlay.death() {
            return Poll::Ready(Err(io::Error::other(reason)));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Один сегмент несёт не больше одного куска. Более длинную запись
        // `AsyncWrite` разрешает отдать по частям — так и поступаем, вместо
        // того чтобы дробить один вызов сразу на несколько сегментов.
        let take = buf.len().min(segment::MAX_FRAGMENT);
        let data = buf[..take].to_vec();
        let underlay = Arc::clone(&this.underlay);
        let state = Arc::clone(&this.state);
        let id = this.id;
        this.sending = Some((
            Box::pin(async move {
                underlay
                    .send_data(id, &state, &data)
                    .await
                    .map_err(io::Error::from)
            }),
            take,
        ));
        this.poll_sending(cx)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_sending(cx).map_ok(|_| ())
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // `closeSessionRequest` здесь не шлётся нарочно — см. документ модуля.
        self.get_mut().poll_sending(cx).map_ok(|_| ())
    }
}

impl Drop for MieruStream {
    fn drop(&mut self) {
        self.underlay.session_closed(self.id);
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;
    use crate::keying::Key;

    /// Поток без сервера: проверяем чтение, а не сеть.
    fn detached() -> (mpsc::Sender<Msg>, MieruStream) {
        let key: Key = [1u8; 32];
        let (client, _server) = tokio::io::duplex(4096);
        let underlay = Underlay::start(1, Box::new(client), &key, Arc::from("тест"));
        let state = Arc::new(SessionState::default());
        let (sender, receiver) = mpsc::channel(4);
        (sender, MieruStream::new(underlay, 1, state, receiver))
    }

    #[tokio::test]
    async fn the_pieces_arrive_in_the_order_they_were_put_in() {
        let (sender, mut stream) = detached();
        sender.send(Msg::Data(Bytes::from("раз"))).await.ok();
        sender.send(Msg::Data(Bytes::from("два"))).await.ok();
        sender.send(Msg::Eof).await.ok();

        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.expect("читается");
        assert_eq!(got, "раздва".as_bytes());
    }

    #[tokio::test]
    async fn a_piece_bigger_than_the_buffer_is_handed_over_in_parts() {
        let (sender, mut stream) = detached();
        sender
            .send(Msg::Data(Bytes::from_static(b"abcdef")))
            .await
            .ok();
        sender.send(Msg::Eof).await.ok();

        let mut small = [0_u8; 2];
        stream.read_exact(&mut small).await.expect("читается");
        assert_eq!(&small, b"ab");

        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.expect("читается");
        assert_eq!(rest, b"cdef");
    }

    #[tokio::test]
    async fn a_queue_that_closed_quietly_is_the_end_of_the_stream() {
        let (sender, mut stream) = detached();
        sender.send(Msg::Data(Bytes::from("хвост"))).await.ok();
        drop(sender);

        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.expect("читается");
        assert_eq!(got, "хвост".as_bytes());
    }
}
