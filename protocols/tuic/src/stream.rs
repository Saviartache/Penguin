//! Поток приложения поверх двустороннего потока QUIC.
//!
//! Работы здесь ровно столько, чтобы свести две половины `quinn` в один
//! [`ProxyStream`](penguin_proto::stream::ProxyStream): читающая и пишущая
//! стороны у него разные объекты, а контракт требует одного.
//!
//! Ни заголовков, ни кадров: команда `Connect` ушла при открытии, ответа на
//! неё нет, и дальше это ровно те байты, что отдало приложение.
//!
//! # Закрытие
//!
//! У QUIC его надо объявлять явно. Поток, который просто перестали писать,
//! для собеседника выглядит живым и молчащим — и висит до срока соединения.
//! Поэтому `poll_shutdown` доводит до `finish`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Поток TUIC: две половины QUIC под одной крышей.
pub struct TuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl std::fmt::Debug for TuicStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuicStream").finish()
    }
}

impl TuicStream {
    /// Сводит половины вместе.
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for TuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for TuicStream {
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
