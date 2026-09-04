//! Поток приложения поверх двустороннего потока QUIC.
//!
//! Работы здесь ровно столько, чтобы свести две половины `quinn` в один
//! [`ProxyStream`](penguin_proto::stream::ProxyStream): читающая и пишущая
//! стороны у него разные объекты, а контракт требует одного.
//!
//! Заголовок ушёл при открытии, ответа на него нет: дальше это ровно те
//! байты, что отдало приложение.
//!
//! # Что здесь ещё держится
//!
//! Соединение, которому поток принадлежит. Не для удобства: эндпойнт QUIC
//! владеет задачей ввода-вывода, и уронить его раньше потока значит оборвать
//! поток на середине.
//!
//! # Закрытие
//!
//! У QUIC его надо объявлять явно. Поток, который просто перестали писать,
//! для собеседника выглядит живым и молчащим — и висит до срока соединения.
//! Поэтому `poll_shutdown` доводит до `finish`.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::link::Link;
use crate::pool;

/// Поток Juicity: две половины QUIC под одной крышей.
pub struct JuicityStream {
    /// Соединение: пока живо оно, жив и эндпойнт под потоком.
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
        // Полное имя, а не короткий вызов: у `quinn::SendStream` есть свой
        // `poll_write` со своей ошибкой, и короткий вызов ушёл бы в него.
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
