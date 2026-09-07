//! Поток GOST Relay: снять заголовок ответа, дальше пропускать как есть.
//!
//! Своих кадров у протокола после заголовков нет — это ровно тот поток байт,
//! который отдало приложение. Вся работа здесь в одном: снять ответный
//! заголовок сервера, и снять его **лениво**.
//!
//! # Почему лениво
//!
//! Сервер (`go-gost/x`, `handler/relay/connect.go`) пишет ответ не сразу
//! после нашего заголовка: при `nodelay = false` — а это умолчание — он
//! склеивает его с первыми данными, которые пришли от адресата. Дождаться
//! ответа до отправки запроса приложения нельзя: данных у сервера ещё нет,
//! потому что запрос приложения ещё не ушёл. Это заклинивание, а не
//! ожидание, и снимается оно только сроком.
//!
//! Поэтому заголовок снимается в первом же [`AsyncRead::poll_read`], до того
//! как приложение увидит хоть байт. Сервер, настроенный отвечать сразу
//! (`nodelay = true`), от этого ничего не теряет: его ответ просто уже лежит
//! в потоке к моменту первого чтения.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{GostRelayError, GostRelayResult};
use crate::frame::{request, response};

/// Сколько байт брать из потока за раз, пока ищем заголовок.
const CHUNK: usize = 8 * 1024;

/// Поток GOST Relay поверх соединения с сервером.
pub struct GostRelayStream<S> {
    io: S,
    /// Прочитанное до того, как заголовок снят.
    ///
    /// После этого не используется: дальше данные идут мимо, прямо в буфер
    /// читателя, — лишняя копия на каждый пакет ни к чему.
    buffered: BytesMut,
    /// Адрес назначения: нужен только тексту ошибки отказа.
    target: String,
    /// Заголовок ответа снят.
    ready: bool,
}

impl<S> std::fmt::Debug for GostRelayStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GostRelayStream")
            .field("target", &self.target)
            .field("ready", &self.ready)
            .finish()
    }
}

impl<S> GostRelayStream<S> {
    /// Оборачивает соединение, в которое уже отправлен заголовок запроса.
    pub fn new(io: S, target: String) -> Self {
        Self {
            io,
            buffered: BytesMut::new(),
            target,
            ready: false,
        }
    }
}

impl<S: AsyncRead + Unpin> GostRelayStream<S> {
    /// Пытается снять заголовок из накопленного.
    ///
    /// `Ok(true)` — снят; `Ok(false)` — байт пока не хватает.
    ///
    /// Признаки ответа дочитываются и отбрасываются, даже когда сервер по
    /// факту ничего в них не кладёт (см. документ [`response`]): иначе один
    /// сервер, который однажды решит что-то туда положить, испортит начало
    /// потока приложения.
    fn take_header(&mut self) -> GostRelayResult<bool> {
        let Some(head) = self.buffered.get(..4) else {
            return Ok(false);
        };
        let head = response::parse_header([head[0], head[1], head[2], head[3]]);

        if head.version != request::VERSION {
            return Err(GostRelayError::malformed(format!(
                "версия ответа {:#04x} вместо {:#04x}",
                head.version,
                request::VERSION
            )));
        }

        let total = 4 + usize::from(head.feature_len);
        if self.buffered.len() < total {
            return Ok(false);
        }
        self.buffered.advance(total);

        match head.status {
            response::STATUS_OK => {
                self.ready = true;
                Ok(true)
            }
            response::STATUS_UNAUTHORIZED => Err(GostRelayError::AuthRejected),
            status => Err(GostRelayError::Refused {
                target: self.target.clone(),
                reason: response::status_text(status),
            }),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for GostRelayStream<S> {
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
                        GostRelayError::malformed("сервер закрыл поток, не ответив на запрос"),
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

impl<S: AsyncWrite + Unpin> AsyncWrite for GostRelayStream<S> {
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
fn as_io(err: GostRelayError) -> io::Error {
    match err {
        GostRelayError::Io(err) => err,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    fn stream<S>(io: S) -> GostRelayStream<S> {
        GostRelayStream::new(io, "example.com:443".to_owned())
    }

    #[tokio::test]
    async fn the_response_header_is_stripped() {
        let (client, mut server) = duplex(4096);
        let mut io = stream(client);

        server
            .write_all(&[request::VERSION, response::STATUS_OK, 0x00, 0x00])
            .await
            .expect("ушло");
        server.write_all(b"payload").await.expect("ушло");

        let mut got = [0u8; 7];
        io.read_exact(&mut got).await.expect("пришло");
        assert_eq!(&got, b"payload");
    }

    #[tokio::test]
    async fn a_successful_response_drains_its_features() {
        let (client, mut server) = duplex(4096);
        let mut io = stream(client);

        server
            .write_all(&[request::VERSION, response::STATUS_OK, 0x00, 0x03])
            .await
            .expect("ушло");
        server.write_all(b"xyzpayload").await.expect("ушло");

        let mut got = [0u8; 7];
        io.read_exact(&mut got).await.expect("пришло");
        assert_eq!(&got, b"payload");
    }

    #[tokio::test]
    async fn nothing_is_read_before_the_server_answers() {
        // Сервер молчит, пока не придут данные от адресата, — и это не
        // повод считать, что ответа не будет: поток обязан ждать, а не
        // падать.
        let (client, mut server) = duplex(4096);
        let mut io = stream(client);

        let mut got = [0u8; 7];
        let read = tokio::spawn(async move {
            io.read_exact(&mut got).await.expect("пришло");
            got
        });

        server
            .write_all(&[request::VERSION, response::STATUS_OK, 0x00, 0x00])
            .await
            .expect("ушло");
        server.write_all(b"payload").await.expect("ушло");

        assert_eq!(&read.await.expect("задача"), b"payload");
    }

    #[tokio::test]
    async fn unauthorized_becomes_auth_rejected() {
        let (client, mut server) = duplex(4096);
        let mut io = stream(client);

        server
            .write_all(&[request::VERSION, response::STATUS_UNAUTHORIZED, 0x00, 0x00])
            .await
            .expect("ушло");

        let err = io.read_u8().await.expect_err("отказ");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("имя"), "{err}");
    }

    #[tokio::test]
    async fn other_statuses_name_the_target() {
        let (client, mut server) = duplex(4096);
        let mut io = stream(client);

        server
            .write_all(&[
                request::VERSION,
                response::STATUS_HOST_UNREACHABLE,
                0x00,
                0x00,
            ])
            .await
            .expect("ушло");

        let err = io.read_u8().await.expect_err("отказ");
        assert!(err.to_string().contains("example.com:443"), "{err}");
    }

    #[tokio::test]
    async fn a_wrong_version_is_not_a_status_to_interpret() {
        // Чужой протокол на этом порту тоже может прислать что-то похожее
        // на успех — версия обязана быть проверена раньше статуса.
        let (client, mut server) = duplex(4096);
        let mut io = stream(client);

        server
            .write_all(&[0x05, response::STATUS_OK, 0x00, 0x00])
            .await
            .expect("ушло");

        let err = io.read_u8().await.expect_err("не то");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_closed_stream_before_the_header_is_not_an_end_of_data() {
        let (client, server) = duplex(4096);
        let mut io = stream(client);
        drop(server);

        let err = io.read_u8().await.expect_err("обрыв");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
