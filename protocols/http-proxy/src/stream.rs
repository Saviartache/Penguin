//! Поток, у которого начало уже прочитано.
//!
//! # Зачем он нужен
//!
//! Ответ прокси на `CONNECT` кончается пустой строкой, а сразу за ней могут
//! идти байты — уже не прокси, а того, к кому он соединил. Так ведут себя все
//! протоколы, где первым говорит сервер: SSH, SMTP, FTP, почти любая база
//! данных.
//!
//! Читать ответ по одному байту, чтобы не захватить лишнего, — это сотня
//! системных вызовов на каждое соединение. Читать пачкой и выбросить остаток —
//! это молча съеденное приветствие сервера, после которого соединение висит,
//! и виноватым выглядит приложение.
//!
//! Поэтому остаток не выбрасывается: он отдаётся первым же чтением, а дальше
//! поток работает как обычно.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Поток с уже прочитанным началом.
#[derive(Debug)]
pub struct Prefixed<S> {
    inner: S,
    head: Vec<u8>,
    /// Сколько из начала уже отдано.
    offset: usize,
}

impl<S> Prefixed<S> {
    /// Приклеивает прочитанное начало обратно к потоку.
    ///
    /// Пустое начало — обычное дело: у прокси, за которым молчаливый сервер,
    /// лишних байт не бывает.
    pub fn new(inner: S, head: Vec<u8>) -> Self {
        Self {
            inner,
            head,
            offset: 0,
        }
    }

    /// Сколько из прочитанного начала ещё не отдано.
    fn left(&self) -> usize {
        self.head.len().saturating_sub(self.offset)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Отдать можно только то, что просят: читатель вправе прийти с
        // буфером на два байта, и положить в него больше — это порча чужой
        // памяти.
        let take = this.left().min(buf.remaining());
        if take > 0 {
            let start = this.offset;
            buf.put_slice(&this.head[start..start + take]);
            this.offset += take;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn the_head_comes_out_before_the_rest() {
        // Ровно то, ради чего всё и заведено: приветствие сервера, попавшее в
        // ответ прокси, обязано дойти до приложения.
        let (client, mut server) = duplex(64);
        server
            .write_all("-остальное".as_bytes())
            .await
            .expect("пишется");

        let mut stream = Prefixed::new(client, "начало".as_bytes().to_vec());
        let mut out = vec![0u8; "начало-остальное".len()];
        stream.read_exact(&mut out).await.expect("читается");

        assert_eq!(String::from_utf8_lossy(&out), "начало-остальное");
    }

    #[tokio::test]
    async fn an_empty_head_changes_nothing() {
        let (client, mut server) = duplex(64);
        server
            .write_all("данные".as_bytes())
            .await
            .expect("пишется");

        let mut stream = Prefixed::new(client, Vec::new());
        let mut out = vec![0u8; "данные".len()];
        stream.read_exact(&mut out).await.expect("читается");
        assert_eq!(String::from_utf8_lossy(&out), "данные");
    }

    #[tokio::test]
    async fn a_head_longer_than_the_buffer_comes_out_in_pieces() {
        // Читатель вправе просить по два байта; отдать больше, чем он просил,
        // значит испортить чужую память.
        let (client, _server) = duplex(64);
        let mut stream = Prefixed::new(client, b"12345".to_vec());

        let mut out = [0u8; 2];
        stream.read_exact(&mut out).await.expect("читается");
        assert_eq!(&out, b"12");
        stream.read_exact(&mut out).await.expect("читается");
        assert_eq!(&out, b"34");
    }
}
