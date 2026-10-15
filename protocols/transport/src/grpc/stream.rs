//! Поток байт поверх сообщений `Hunk`: запись — по кадру gRPC на кусок,
//! чтение — данные кадров подряд.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::frame::{Deframer, encode_hunk};

/// Самый большой кусок в одном `Hunk`.
const MAX_HUNK: usize = 16 * 1024;

/// Размер одного чтения из тела ответа.
const READ_CHUNK: usize = 16 * 1024;

/// Туннель gRPC поверх тела запроса и ответа `S`.
pub struct GrpcStream<S> {
    inner: S,
    deframer: Deframer,
    /// Данные последнего `Hunk`, ещё не отданные читателю.
    leftover: Bytes,
    scratch: Box<[u8]>,
    /// Собранный кадр, ещё не ушедший целиком.
    pending: Bytes,
    /// Сколько байт тела в этом кадре.
    pending_len: usize,
}

impl<S> GrpcStream<S> {
    /// Оборачивает поток тела.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            deframer: Deframer::default(),
            leftover: Bytes::new(),
            scratch: vec![0; READ_CHUNK].into_boxed_slice(),
            pending: Bytes::new(),
            pending_len: 0,
        }
    }
}

impl<S: AsyncWrite + Unpin> GrpcStream<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let written = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending.advance(written);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for GrpcStream<S> {
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
            if let Some(data) = this.deframer.next_hunk().map_err(io::Error::other)? {
                this.leftover = data;
                continue;
            }
            let mut chunk = ReadBuf::new(&mut this.scratch);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut chunk))?;
            if chunk.filled().is_empty() {
                // Конец тела: дальше читать нечего.
                return Poll::Ready(Ok(()));
            }
            this.deframer.push(chunk.filled());
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for GrpcStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending.is_empty() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let chunk = &buf[..buf.len().min(MAX_HUNK)];
            this.pending = encode_hunk(chunk);
            this.pending_len = chunk.len();
        }
        // Запись сделана, когда кадр ушёл целиком; повтор после `Pending`
        // приходит с теми же байтами.
        ready!(this.poll_drain(cx))?;
        Poll::Ready(Ok(this.pending_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn writes_become_hunks_and_hunks_become_reads() {
        let (client, mut server) = duplex(1 << 16);
        let mut stream = GrpcStream::new(client);

        stream.write_all(b"hello").await.expect("запись");
        let mut wire = [0u8; 12];
        server.read_exact(&mut wire).await.expect("кадр");
        assert_eq!(
            &wire,
            &[0, 0, 0, 0, 7, 0x0a, 5, b'h', b'e', b'l', b'l', b'o']
        );

        server.write_all(&encode_hunk(b"wor")).await.expect("ответ");
        server.write_all(&encode_hunk(b"ld")).await.expect("ответ");
        drop(server);
        let mut read = Vec::new();
        stream.read_to_end(&mut read).await.expect("чтение");
        assert_eq!(read, b"world");
    }
}
