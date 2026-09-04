//! Поток приложения внутри сессии.
//!
//! Снаружи это обычный [`ProxyStream`](penguin_proto::stream::ProxyStream):
//! читают из очереди, которую наполняет задача чтения сессии, пишут кадрами
//! `cmdPSH`.
//!
//! # Отчего запись выглядит так
//!
//! Писать в сессию можно только под её замком, а замок асинхронный —
//! `poll_write` же синхронный. Поэтому кадр собирается сразу, а отправка
//! живёт отложенной задачей внутри потока: пока она не кончилась, поток
//! доводит именно её и новых байт не берёт.
//!
//! # Закрытие
//!
//! `poll_shutdown` **не** закрывает поток: `cmdFIN` у AnyTLS закрывает его
//! целиком, в обе стороны, и сервер удалил бы поток раньше, чем ответил.
//! Закрывается он в `Drop` — тогда, когда ответ уже никому не нужен.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::frame;
use crate::session::{Msg, Session};

/// Отложенная отправка кадра.
type Sending = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

/// Поток AnyTLS.
pub struct AnyTlsStream {
    session: Arc<Session>,
    id: u32,
    /// Что пришло из сессии.
    incoming: mpsc::Receiver<Msg>,
    /// Прочитанное, но не отданное приложению.
    leftover: Bytes,
    /// Собеседник закончил.
    finished: bool,
    /// Кадр, который сейчас отправляется, и сколько байт он унёс.
    sending: Option<(Sending, usize)>,
}

impl std::fmt::Debug for AnyTlsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsStream")
            .field("session", &self.session.seq())
            .field("id", &self.id)
            .finish()
    }
}

impl AnyTlsStream {
    /// Собирает поток. Зовёт его только [`Session::open_stream`].
    pub(crate) fn new(session: Arc<Session>, id: u32, incoming: mpsc::Receiver<Msg>) -> Self {
        Self {
            session,
            id,
            incoming,
            leftover: Bytes::new(),
            finished: false,
            sending: None,
        }
    }

    /// Номер потока в сессии.
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

impl AsyncRead for AnyTlsStream {
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
                Poll::Ready(Some(Msg::Failed(reason))) => {
                    this.finished = true;
                    return Poll::Ready(Err(io::Error::other(reason)));
                }
                // Очередь закрылась без прощания: либо поток сняли, либо
                // умерла вся сессия. Первое — конец, второе — обрыв, и
                // путать их значит показывать обрыв успехом.
                Poll::Ready(None) => {
                    this.finished = true;
                    return Poll::Ready(match this.session.death() {
                        Some(reason) => Err(io::Error::other(reason)),
                        None => Ok(()),
                    });
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for AnyTlsStream {
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
        if let Some(reason) = this.session.death() {
            return Poll::Ready(Err(io::Error::other(reason)));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let take = buf.len().min(frame::MAX_PAYLOAD);
        let data = buf[..take].to_vec();
        let session = Arc::clone(&this.session);
        let id = this.id;
        this.sending = Some((
            Box::pin(async move {
                session
                    .write_frame(frame::CMD_PSH, id, &data)
                    .await
                    .map_err(io::Error::from)
            }),
            take,
        ));
        this.poll_sending(cx)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Каждая запись уходит из сессии со сбросом — иначе схема дополнения
        // не значила бы ничего. Сбрасывать нечего, кроме начатой отправки.
        self.get_mut().poll_sending(cx).map_ok(|_| ())
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // `cmdFIN` здесь не шлётся нарочно: он закрывает поток в обе стороны,
        // и ответ сервера пришёл бы уже некуда (см. документ модуля).
        self.get_mut().poll_sending(cx).map_ok(|_| ())
    }
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        self.session.stream_closed(self.id);
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    /// Поток без сессии: проверяем чтение, а не сеть.
    fn detached() -> (mpsc::Sender<Msg>, AnyTlsStream) {
        let padding = Arc::new(crate::padding::Padding::new());
        let (client, _server) = tokio::io::duplex(4096);
        let session = Session::start(
            1,
            Box::new(client),
            padding,
            "penguin/тест",
            std::sync::Weak::new(),
        )
        .expect("сессия поднимается");

        let (sender, receiver) = mpsc::channel(4);
        (sender, AnyTlsStream::new(session, 1, receiver))
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
    async fn a_refusal_from_the_server_comes_out_as_an_error() {
        // Иначе «сервер не смог соединиться» выглядело бы пустым ответом, и
        // браузер показал бы пустую страницу вместо ошибки.
        let (sender, mut stream) = detached();
        sender
            .send(Msg::Failed("connection refused".into()))
            .await
            .ok();

        let mut got = Vec::new();
        let err = stream.read_to_end(&mut got).await.expect_err("это ошибка");
        assert!(err.to_string().contains("refused"), "{err}");
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
