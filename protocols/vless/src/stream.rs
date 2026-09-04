//! Поток VLESS: снять заголовок ответа, дальше пропускать как есть.
//!
//! Своего шифрования у VLESS нет, кадров тоже — после заголовков это ровно тот
//! поток байт, который отдало приложение. Вся работа здесь в одном: снять
//! ответный заголовок сервера, и снять его **лениво**.
//!
//! # Почему лениво
//!
//! Сервер шлёт свой заголовок не в ответ на наш, а вместе с первыми данными.
//! Прочитать его сразу после отправки запроса нельзя: данных ещё нет, и
//! чтение повисло бы до тех пор, пока приложение что-нибудь не спросит, — то
//! есть навсегда для протоколов, где первым говорит сервер.
//!
//! Поэтому заголовок снимается в первом же [`AsyncRead::poll_read`], до того
//! как приложение увидит хоть байт.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::VlessError;
use crate::frame::request;

/// Сколько байт брать из потока за раз, пока ищем заголовок.
const CHUNK: usize = 8 * 1024;

/// Поток VLESS поверх соединения с сервером.
pub struct VlessStream<S> {
    io: S,
    /// Прочитанное до того, как заголовок снят.
    ///
    /// После этого не используется: дальше данные идут мимо, прямо в буфер
    /// читателя, — лишняя копия на каждый пакет ни к чему.
    buffered: BytesMut,
    /// Заголовок ответа снят.
    ready: bool,
}

impl<S> std::fmt::Debug for VlessStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessStream")
            .field("ready", &self.ready)
            .finish()
    }
}

impl<S> VlessStream<S> {
    /// Оборачивает соединение, в которое уже отправлен заголовок запроса.
    pub fn new(io: S) -> Self {
        Self {
            io,
            buffered: BytesMut::new(),
            ready: false,
        }
    }
}

impl<S: AsyncRead + Unpin> VlessStream<S> {
    /// Пытается снять заголовок из накопленного.
    ///
    /// `Ok(true)` — снят; `Ok(false)` — байт пока не хватает.
    fn take_header(&mut self) -> Result<bool, VlessError> {
        match request::response_len(&self.buffered)? {
            Some(len) => {
                self.buffered.advance(len);
                self.ready = true;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        while !this.ready {
            match this.take_header() {
                Ok(true) => break,
                Ok(false) => {}
                Err(err) => return Poll::Ready(Err(as_io(err))),
            }

            let before = this.buffered.len();
            this.buffered.resize(before + CHUNK, 0);
            let mut chunk = ReadBuf::new(&mut this.buffered[before..]);

            let result = Pin::new(&mut this.io).poll_read(cx, &mut chunk);
            let filled = chunk.filled().len();
            this.buffered.truncate(before + filled);

            match result {
                Poll::Ready(Ok(())) if filled == 0 => {
                    // Сервер закрылся, не прислав заголовка. Это не «конец
                    // данных»: до данных дело даже не дошло.
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        VlessError::Disconnected(
                            "сервер закрыл поток, не ответив на запрос".to_owned(),
                        ),
                    )));
                }
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Что успело прийти вместе с заголовком, отдаётся первым: иначе оно
        // потерялось бы, а это начало ответа сервера.
        if !this.buffered.is_empty() {
            let take = this.buffered.len().min(buf.remaining());
            buf.put_slice(&this.buffered[..take]);
            this.buffered.advance(take);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut this.io).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessStream<S> {
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

/// Ошибка протокола в языке, на котором говорят [`AsyncRead`] и [`AsyncWrite`].
fn as_io(err: VlessError) -> io::Error {
    match err {
        VlessError::Io(err) => err,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn the_response_header_is_stripped() {
        let (client, mut server) = duplex(4096);
        let mut stream = VlessStream::new(client);

        server.write_all(&[0x00, 0x00]).await.expect("ушло");
        server.write_all(b"payload").await.expect("ушло");

        let mut got = [0u8; 7];
        stream.read_exact(&mut got).await.expect("пришло");
        assert_eq!(&got, b"payload");
    }

    #[tokio::test]
    async fn addons_in_the_response_are_skipped() {
        let (client, mut server) = duplex(4096);
        let mut stream = VlessStream::new(client);

        server
            .write_all(&[0x00, 0x03, 1, 2, 3])
            .await
            .expect("ушло");
        server.write_all(b"payload").await.expect("ушло");

        let mut got = [0u8; 7];
        stream.read_exact(&mut got).await.expect("пришло");
        assert_eq!(&got, b"payload");
    }

    #[tokio::test]
    async fn data_arriving_with_the_header_is_not_lost() {
        // Заголовок и первые данные приходят одним пакетом — так бывает
        // почти всегда.
        let (client, mut server) = duplex(4096);
        let mut stream = VlessStream::new(client);

        let mut wire = vec![0x00, 0x00];
        wire.extend_from_slice(b"payload");
        server.write_all(&wire).await.expect("ушло");

        let mut got = [0u8; 7];
        stream.read_exact(&mut got).await.expect("пришло");
        assert_eq!(&got, b"payload");
    }

    #[tokio::test]
    async fn a_header_split_across_packets_is_assembled() {
        let (client, mut server) = duplex(4096);
        let mut stream = VlessStream::new(client);

        let reader = tokio::spawn(async move {
            let mut got = [0u8; 7];
            stream.read_exact(&mut got).await.expect("пришло");
            got
        });

        for byte in [0x00, 0x02, 0xAA, 0xBB] {
            server.write_all(&[byte]).await.expect("ушло");
        }
        server.write_all(b"payload").await.expect("ушло");

        assert_eq!(&reader.await.expect("задача"), b"payload");
    }

    #[tokio::test]
    async fn what_we_write_goes_out_untouched() {
        // Своего шифрования и своих кадров у VLESS нет: после заголовка это
        // ровно те байты, что отдало приложение.
        let (client, mut server) = duplex(4096);
        let mut stream = VlessStream::new(client);

        stream.write_all(b"request").await.expect("ушло");
        stream.flush().await.expect("сброшено");

        let mut got = [0u8; 7];
        server.read_exact(&mut got).await.expect("пришло");
        assert_eq!(&got, b"request");
    }

    #[tokio::test]
    async fn an_ordinary_web_page_is_told_apart() {
        // Самая частая ошибка настройки — не тот адрес: на нём сидит сайт, и
        // отвечает он страницей.
        let (client, mut server) = duplex(4096);
        let mut stream = VlessStream::new(client);

        server
            .write_all(b"HTTP/1.1 400 Bad Request\r\n")
            .await
            .expect("ушло");

        let mut got = [0u8; 4];
        let err = stream.read_exact(&mut got).await.expect_err("это не VLESS");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_server_that_closes_without_answering_is_an_error() {
        // Не «конец данных»: до данных дело даже не дошло, и молчаливый конец
        // выглядел бы для приложения пустым, но успешным ответом.
        let (client, server) = duplex(4096);
        let mut stream = VlessStream::new(client);
        drop(server);

        let mut got = Vec::new();
        let err = stream.read_to_end(&mut got).await.expect_err("оборвано");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
