//! Поток приложения внутри сессии.
//!
//! Снаружи это обычный [`ProxyStream`](penguin_proto::stream::ProxyStream):
//! читают из очереди, которую наполняет задача разбора, пишут кадрами
//! [`frame::DATA`].
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
//! У Pingwin оно раздельное, в отличие от AnyTLS: `poll_shutdown` шлёт
//! [`frame::FIN`] — «с этой стороны данных больше не будет», — и обратное
//! направление продолжает работать. Так устроен обычный TCP, и приложение,
//! которое говорит «я всё сказал» и ждёт ответа, через Pingwin его дождётся.
//!
//! [`frame::RST`] уходит в `Drop` и только тогда, когда поток бросили,
//! не договорив: без него собеседник держал бы соединение к цели вечно.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::mux::session::{Msg, Session};
use crate::wire::frame;

/// Отложенная отправка кадра.
type Sending = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

/// Поток Pingwin.
pub struct PingwinStream {
    session: Arc<Session>,
    id: u32,
    /// Что пришло из сессии.
    incoming: mpsc::Receiver<Msg>,
    /// Прочитанное, но не отданное приложению.
    leftover: Bytes,
    /// Собеседник закончил.
    finished: bool,
    /// Мы закончили.
    fin_sent: bool,
    /// Кадр, который сейчас отправляется, и сколько байт он унёс.
    sending: Option<(Sending, usize)>,
}

impl std::fmt::Debug for PingwinStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PingwinStream")
            .field("id", &self.id)
            .field("finished", &self.finished)
            .finish()
    }
}

impl PingwinStream {
    /// Собирает поток. Зовут его только [`Session`] и её просьбы.
    pub(crate) fn new(session: Arc<Session>, id: u32, incoming: mpsc::Receiver<Msg>) -> Self {
        Self {
            session,
            id,
            incoming,
            leftover: Bytes::new(),
            finished: false,
            fin_sent: false,
            sending: None,
        }
    }

    /// Номер потока в сессии.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Начинает отправку кадра.
    fn start(&self, cmd: u8, data: Vec<u8>) -> Sending {
        let session = Arc::clone(&self.session);
        let id = self.id;
        Box::pin(async move { session.send(cmd, id, &data).await.map_err(io::Error::from) })
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

impl AsyncRead for PingwinStream {
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
                // Очередь закрылась вместе с сессией: причина уже сказана
                // тем сообщением, которое пришло раньше, либо её нет вовсе.
                Poll::Ready(None) => {
                    this.finished = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for PingwinStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.sending.is_some() {
            return this.poll_sending(cx);
        }
        if this.fin_sent {
            return Poll::Ready(Err(io::Error::other(
                "поток уже закрыт с этой стороны".to_owned(),
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let take = buf.len().min(frame::MAX_PAYLOAD);
        let sending = this.start(frame::DATA, buf[..take].to_vec());
        this.sending = Some((sending, take));
        this.poll_sending(cx)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Запись уходит в сокет целиком уже в `poll_write`: сбрасывать нечего,
        // кроме кадра, который ещё летит.
        self.get_mut().poll_sending(cx).map_ok(|_| ())
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.sending.is_some() {
            return this.poll_sending(cx).map_ok(|_| ());
        }
        if this.fin_sent {
            return Poll::Ready(Ok(()));
        }
        this.fin_sent = true;
        this.sending = Some((this.start(frame::FIN, Vec::new()), 0));
        this.poll_sending(cx).map_ok(|_| ())
    }
}

impl Drop for PingwinStream {
    fn drop(&mut self) {
        self.session.forget(self.id);

        // Договорили обе стороны — обрывать нечего. В любом другом случае
        // собеседник обязан узнать, что поток брошен, иначе он будет держать
        // соединение к цели, пока не кончится терпение системы.
        if self.fin_sent && self.finished {
            return;
        }
        if self.session.is_dead() {
            return;
        }
        // Через `Handle`, а не `tokio::spawn`: `Drop` зовут откуда угодно, в
        // том числе с потока без рантайма, и `spawn` там не возвращает ошибку,
        // а паникует — в деструкторе это худший из возможных исходов.
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let session = Arc::clone(&self.session);
        let id = self.id;
        runtime.spawn(async move {
            let _ = session
                .send(frame::RST, id, "поток брошен".as_bytes())
                .await;
        });
    }
}
