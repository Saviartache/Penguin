//! Поток приложения: тот же поток, только с ответом сервера впереди.
//!
//! Ответ — один байт, и снимается он **при первом чтении**, а не при
//! открытии. Причина не в лени: сервер шлёт его, когда соединится с адресом
//! назначения, и ждать его перед отправкой данных значило бы платить лишним
//! оборотом до сервера на каждое соединение.
//!
//! Отсюда следствие, которое надо знать: отказ сервера («не разрешается имя»,
//! «отказано в соединении») приходит не из `connect_tcp`, а из первого
//! `read`. Приложение видит его ошибкой чтения — так же, как если бы
//! соединение оборвалось.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use penguin_proto::stream::ProxyStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::frame::reply;

/// Сколько байт брать из потока за раз, пока ответ не снят.
const READ_CHUNK: usize = 4 * 1024;

/// Поток Snell поверх кадра.
pub struct SnellStream {
    io: Box<dyn ProxyStream>,
    /// Прочитанное, ещё не разобранное и не отданное.
    pending: BytesMut,
    /// Ответ уже снят.
    answered: bool,
}

impl std::fmt::Debug for SnellStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnellStream")
            .field("answered", &self.answered)
            .finish()
    }
}

impl SnellStream {
    /// Оборачивает поток, в который уже отправлен заголовок.
    pub fn new(io: Box<dyn ProxyStream>) -> Self {
        Self {
            io,
            pending: BytesMut::new(),
            answered: false,
        }
    }
}

impl AsyncRead for SnellStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            if this.answered {
                if !this.pending.is_empty() {
                    let take = this.pending.len().min(buf.remaining());
                    buf.put_slice(&this.pending[..take]);
                    this.pending.advance(take);
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut this.io).poll_read(cx, buf);
            }

            match reply::decode(&this.pending) {
                Ok(Some((reply, used))) => {
                    this.pending.advance(used);
                    if let Err(err) = reply.into_result() {
                        return Poll::Ready(Err(err.into()));
                    }
                    this.answered = true;
                    continue;
                }
                Ok(None) => {}
                Err(err) => return Poll::Ready(Err(err.into())),
            }

            let before = this.pending.len();
            this.pending.resize(before + READ_CHUNK, 0);
            let mut chunk = ReadBuf::new(&mut this.pending[before..]);

            let result = Pin::new(&mut this.io).poll_read(cx, &mut chunk);
            let filled = chunk.filled().len();
            this.pending.truncate(before + filled);

            match result {
                Poll::Ready(Ok(())) if filled == 0 => {
                    // Сервер закрыл соединение, не сказав ни слова. Чаще
                    // всего это неверный PSK: расшифровать наш заголовок он
                    // не смог, а отказ шлют только те, кто смог.
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                }
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for SnellStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;

    fn pair() -> (SnellStream, DuplexStream) {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        (SnellStream::new(Box::new(ours)), theirs)
    }

    #[tokio::test]
    async fn the_reply_is_stripped_and_the_data_stays() {
        let (mut stream, mut peer) = pair();
        let mut wire = vec![reply::TUNNEL];
        wire.extend_from_slice(b"payload");
        peer.write_all(&wire).await.expect("пишется");

        let mut got = [0u8; 7];
        stream.read_exact(&mut got).await.expect("читается");
        assert_eq!(&got, b"payload");
    }

    #[tokio::test]
    async fn the_reply_arriving_alone_does_not_look_like_the_end() {
        // Ответ приходит, когда сервер соединился; данные — позже. Принять
        // это за конец потока значило бы обрывать каждое соединение.
        let (mut stream, mut peer) = pair();
        peer.write_all(&[reply::TUNNEL]).await.expect("пишется");
        peer.flush().await.expect("уходит");

        let reader = tokio::spawn(async move {
            let mut got = [0u8; 4];
            stream.read_exact(&mut got).await.expect("читается");
            got
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        peer.write_all(b"late").await.expect("пишется");
        assert_eq!(&reader.await.expect("задача"), b"late");
    }

    #[tokio::test]
    async fn a_refusal_comes_out_as_an_error_with_its_text() {
        let (mut stream, mut peer) = pair();
        let mut wire = vec![reply::ERROR, 4, 11];
        wire.extend_from_slice(b"no such dns");
        peer.write_all(&wire).await.expect("пишется");

        let mut got = Vec::new();
        let err = stream.read_to_end(&mut got).await.expect_err("это отказ");
        assert!(err.to_string().contains("no such dns"), "{err}");
    }

    #[tokio::test]
    async fn a_server_that_says_nothing_is_an_error_and_not_a_clean_end() {
        // Чаще всего это неверный PSK: расшифровать заголовок сервер не смог,
        // а отказ шлют только те, кто смог.
        let (mut stream, peer) = pair();
        drop(peer);

        let mut got = Vec::new();
        let err = stream.read_to_end(&mut got).await.expect_err("молчание");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn an_answer_nobody_speaks_is_reported() {
        let (mut stream, mut peer) = pair();
        peer.write_all(&[0x42, 0x42]).await.expect("пишется");

        let mut got = Vec::new();
        let err = stream
            .read_to_end(&mut got)
            .await
            .expect_err("не тот ответ");
        assert!(err.to_string().contains("не эта его версия"), "{err}");
    }

    #[tokio::test]
    async fn writing_needs_no_reply_and_does_not_wait_for_one() {
        // Заголовок и первые данные уходят до того, как сервер ответил, —
        // иначе каждое соединение стоило бы лишнего оборота.
        let (mut stream, mut peer) = pair();
        stream.write_all(b"early").await.expect("пишется");
        stream.flush().await.expect("уходит");

        let mut got = [0u8; 5];
        peer.read_exact(&mut got).await.expect("читается");
        assert_eq!(&got, b"early");
    }
}
