//! Поток поверх кадров WebSocket.
//!
//! Снаружи это обычный [`AsyncRead`] + [`AsyncWrite`], то есть готовый
//! [`ProxyStream`](penguin_proto::stream::ProxyStream). Кадры, маска и
//! управляющие сообщения остаются внутри: протоколу поверх них знать о них
//! незачем.
//!
//! # Что здесь решается, кроме разбора кадров
//!
//! **Границы кадров — не границы записей.** Приложение пишет как ему удобно,
//! и один его `write` может стать несколькими кадрами, а один кадр —
//! несколькими `read`. Поток байт это и означает.
//!
//! **`ping` надо отвечать.** Сервер, не получивший `pong`, через минуту
//! закрывает соединение, и выглядит это как «прокси рвёт связь на ровном
//! месте». Ответ ставится в очередь отправки и уходит при первой возможности:
//! ждать его отправки внутри чтения нельзя — читатель и писатель работают
//! независимо, и ожидание здесь означало бы взаимную блокировку.
//!
//! **Обрыв посреди кадра — это ошибка, а не конец потока.** Половина
//! заголовка, за которой закрылся сокет, означает потерянные данные; отдать
//! её наверх как обычный конец файла значит показать приложению неполный
//! ответ как полный.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::frame::{self, Header};
use crate::error::TransportError;

/// Сколько байт брать из сокета за раз.
const CHUNK: usize = 16 * 1024;

/// Сколько байт исходящих кадров можно накопить, прежде чем перестать
/// принимать новые.
///
/// Без предела медленный сервер набивал бы нам память ровно с той скоростью,
/// с какой приложение пишет.
const OUT_LIMIT: usize = 256 * 1024;

/// Поток байт поверх кадров WebSocket.
pub struct WsStream<S> {
    io: S,
    /// Сырые байты от сервера, ещё не разобранные в кадры.
    incoming: BytesMut,
    /// Данные, разобранные из кадра и ещё не отданные читателю.
    ready: BytesMut,
    /// Собранные кадры, ещё не ушедшие в сокет.
    outgoing: BytesMut,
    /// Сервер прислал закрытие.
    closing: bool,
    /// Закрытие отправлено.
    closed: bool,
}

impl<S> std::fmt::Debug for WsStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsStream")
            .field("ready", &self.ready.len())
            .field("outgoing", &self.outgoing.len())
            .field("closing", &self.closing)
            .finish()
    }
}

impl<S> WsStream<S> {
    /// Оборачивает соединение, по которому рукопожатие уже прошло.
    ///
    /// `tail` — байты, пришедшие следом за ответом сервера: он вправе прислать
    /// первый кадр тем же пакетом, и потерять их значит потерять начало
    /// соединения.
    pub fn new(io: S, tail: Vec<u8>) -> Self {
        Self {
            io,
            incoming: BytesMut::from(&tail[..]),
            ready: BytesMut::new(),
            outgoing: BytesMut::new(),
            closing: false,
            closed: false,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsStream<S> {
    /// Дописывает в сокет всё, что накопилось.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.outgoing.is_empty() {
            match Pin::new(&mut self.io).poll_write(cx, &self.outgoing) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(written)) => self.outgoing.advance(written),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Ставит кадр в очередь отправки.
    fn queue(&mut self, opcode: u8, payload: &[u8]) {
        let mut out = Vec::with_capacity(payload.len() + 14);
        frame::encode(opcode, true, payload, new_mask(), &mut out);
        self.outgoing.extend_from_slice(&out);
    }

    /// Разбирает один кадр из накопленного, если он пришёл целиком.
    ///
    /// `Ok(false)` — байт пока не хватает.
    fn take_frame(&mut self, cx: &mut Context<'_>) -> Result<bool, TransportError> {
        let Some(header) = frame::decode_header(&self.incoming)? else {
            return Ok(false);
        };
        if self.incoming.len() < header.total_len() {
            return Ok(false);
        }

        let mut payload = self.incoming[header.header_len..header.total_len()].to_vec();
        self.incoming.advance(header.total_len());
        if header.masked {
            frame::apply_mask(&mut payload, header.mask, 0);
        }

        self.handle(header, payload, cx)?;
        Ok(true)
    }

    /// Что делать с разобранным кадром.
    fn handle(
        &mut self,
        header: Header,
        payload: Vec<u8>,
        cx: &mut Context<'_>,
    ) -> Result<(), TransportError> {
        match header.opcode {
            frame::OP_BINARY | frame::OP_TEXT | frame::OP_CONTINUATION => {
                // Продолжение обрабатывается наравне с началом: снаружи это
                // поток байт, и границы сообщения в нём ничего не значат.
                self.ready.extend_from_slice(&payload);
            }
            frame::OP_PING => {
                self.queue(frame::OP_PONG, &payload);
                // Попытка отправить сразу. Не вышло — уйдёт при первой
                // возможности; ждать здесь нельзя.
                let _ = self.poll_drain(cx);
            }
            frame::OP_PONG => {}
            frame::OP_CLOSE => {
                self.closing = true;
                if !self.closed {
                    // Ответное закрытие: без него сервер ждёт его до
                    // истечения своего срока, держа сессию.
                    self.queue(frame::OP_CLOSE, &[]);
                    self.closed = true;
                    let _ = self.poll_drain(cx);
                }
            }
            other => {
                return Err(TransportError::malformed(format!(
                    "неизвестный код кадра {other:#x}"
                )));
            }
        }
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            if !this.ready.is_empty() {
                let take = this.ready.len().min(buf.remaining());
                buf.put_slice(&this.ready[..take]);
                this.ready.advance(take);
                return Poll::Ready(Ok(()));
            }
            if this.closing {
                return Poll::Ready(Ok(()));
            }

            match this.take_frame(cx) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(err) => return Poll::Ready(Err(as_io(err))),
            }

            // Кадра целиком нет — читаем ещё.
            let before = this.incoming.len();
            this.incoming.resize(before + CHUNK, 0);
            let mut chunk = ReadBuf::new(&mut this.incoming[before..]);

            let result = Pin::new(&mut this.io).poll_read(cx, &mut chunk);
            let filled = chunk.filled().len();
            this.incoming.truncate(before + filled);

            match result {
                Poll::Ready(Ok(())) if filled == 0 => {
                    // Обрыв посреди кадра — потерянные данные, и отдать их
                    // наверх как обычный конец потока значит показать
                    // приложению неполный ответ как полный.
                    return Poll::Ready(if this.incoming.is_empty() {
                        Ok(())
                    } else {
                        Err(io::Error::from(io::ErrorKind::UnexpectedEof))
                    });
                }
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Накопилось слишком много — сначала отдать это в сокет. Иначе
        // медленный сервер набивал бы память со скоростью записи приложения.
        if this.outgoing.len() >= OUT_LIMIT {
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let take = buf.len().min(frame::MAX_SEND);
        this.queue(frame::OP_BINARY, &buf[..take]);
        // Кадр собран и принадлежит нам: байты можно считать записанными, а
        // сокет догонит на `poll_flush`.
        let _ = this.poll_drain(cx);
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.closed {
            this.queue(frame::OP_CLOSE, &[]);
            this.closed = true;
        }
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_shutdown(cx),
            other => other,
        }
    }
}

/// Свежий ключ маски.
fn new_mask() -> [u8; 4] {
    use rand::Rng;
    rand::thread_rng().r#gen()
}

/// Ошибка транспорта в языке, на котором говорят [`AsyncRead`] и [`AsyncWrite`].
fn as_io(err: TransportError) -> io::Error {
    match err {
        TransportError::Io(err) => err,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    /// Собирает кадр так, как его прислал бы сервер: без маски.
    fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80 | opcode];
        let len = payload.len();
        if len < 126 {
            out.push(len as u8);
        } else {
            out.push(126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    /// Разбирает то, что клиент отправил серверу.
    fn read_client_frames(mut bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        while let Some(header) = frame::decode_header(bytes).expect("не сломано") {
            if bytes.len() < header.total_len() {
                break;
            }
            let mut payload = bytes[header.header_len..header.total_len()].to_vec();
            assert!(header.masked, "клиент обязан маскировать");
            frame::apply_mask(&mut payload, header.mask, 0);
            out.push((header.opcode, payload));
            bytes = &bytes[header.total_len()..];
        }
        out
    }

    #[tokio::test]
    async fn data_arrives_whole_across_frames() {
        // Границы кадров — не границы записей: снаружи это поток байт.
        let (client, mut server) = duplex(64 * 1024);
        let mut ws = WsStream::new(client, Vec::new());

        server
            .write_all(&server_frame(frame::OP_BINARY, b"first "))
            .await
            .unwrap();
        server
            .write_all(&server_frame(frame::OP_CONTINUATION, b"second"))
            .await
            .unwrap();

        let mut got = [0u8; 12];
        ws.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"first second");
    }

    #[tokio::test]
    async fn the_tail_of_the_handshake_is_not_lost() {
        // Сервер вправе прислать первый кадр тем же пакетом, что и ответ.
        let (client, _server) = duplex(1024);
        let mut ws = WsStream::new(client, server_frame(frame::OP_BINARY, "привет".as_bytes()));

        let mut got = vec![0u8; "привет".len()];
        ws.read_exact(&mut got).await.unwrap();
        assert_eq!(got, "привет".as_bytes());
    }

    #[tokio::test]
    async fn what_we_write_goes_out_masked() {
        let (client, mut server) = duplex(64 * 1024);
        let mut ws = WsStream::new(client, Vec::new());

        ws.write_all("данные".as_bytes()).await.unwrap();
        ws.flush().await.unwrap();

        let mut raw = vec![0u8; 64];
        let read = server.read(&mut raw).await.unwrap();
        let frames = read_client_frames(&raw[..read]);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, frame::OP_BINARY);
        assert_eq!(frames[0].1, "данные".as_bytes());
    }

    #[tokio::test]
    async fn a_ping_is_answered() {
        // Сервер, не получивший `pong`, закрывает соединение, и выглядит это
        // как «прокси рвёт связь на ровном месте».
        let (client, mut server) = duplex(64 * 1024);
        let mut ws = WsStream::new(client, Vec::new());

        server
            .write_all(&server_frame(frame::OP_PING, "проверка".as_bytes()))
            .await
            .unwrap();
        server
            .write_all(&server_frame(frame::OP_BINARY, b"data"))
            .await
            .unwrap();

        let mut got = [0u8; 4];
        ws.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"data");

        let mut raw = vec![0u8; 64];
        let read = server.read(&mut raw).await.unwrap();
        let frames = read_client_frames(&raw[..read]);
        assert_eq!(frames[0].0, frame::OP_PONG);
        assert_eq!(frames[0].1, "проверка".as_bytes());
    }

    #[tokio::test]
    async fn a_close_from_the_server_ends_the_stream() {
        let (client, mut server) = duplex(64 * 1024);
        let mut ws = WsStream::new(client, Vec::new());

        server
            .write_all(&server_frame(frame::OP_CLOSE, &[]))
            .await
            .unwrap();

        let mut got = Vec::new();
        ws.read_to_end(&mut got).await.unwrap();
        assert!(got.is_empty());

        let mut raw = vec![0u8; 64];
        let read = server.read(&mut raw).await.unwrap();
        let frames = read_client_frames(&raw[..read]);
        assert_eq!(frames[0].0, frame::OP_CLOSE, "закрытие не подтверждено");
    }

    #[tokio::test]
    async fn a_connection_cut_mid_frame_is_an_error() {
        // Половина заголовка, за которой закрылся сокет, — это потерянные
        // данные, а не конец потока.
        let (client, mut server) = duplex(1024);
        let mut ws = WsStream::new(client, Vec::new());

        server.write_all(&[0x82, 0x10, 1, 2, 3]).await.unwrap();
        drop(server);

        let mut got = Vec::new();
        let err = ws.read_to_end(&mut got).await.expect_err("оборвано");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn a_clean_close_of_the_socket_is_the_end_of_the_stream() {
        let (client, server) = duplex(1024);
        let mut ws = WsStream::new(client, Vec::new());
        drop(server);

        let mut got = Vec::new();
        ws.read_to_end(&mut got).await.expect("чистый конец");
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn a_long_write_is_cut_into_frames() {
        // Приложение пишет как ему удобно; держать мегабайт одним кадром
        // незачем.
        let (client, mut server) = duplex(1024 * 1024);
        let mut ws = WsStream::new(client, Vec::new());

        let payload = vec![7u8; frame::MAX_SEND + 1000];
        ws.write_all(&payload).await.unwrap();
        ws.flush().await.unwrap();

        let mut raw = vec![0u8; payload.len() + 64];
        let mut read = 0;
        while read < payload.len() {
            read += server.read(&mut raw[read..]).await.unwrap();
        }

        let frames = read_client_frames(&raw[..read]);
        assert_eq!(frames.len(), 2, "кадр не разрезан");
        assert_eq!(frames[0].1.len(), frame::MAX_SEND);
        assert_eq!(frames[1].1.len(), 1000);
    }

    #[tokio::test]
    async fn an_unknown_opcode_is_reported() {
        let (client, mut server) = duplex(1024);
        let mut ws = WsStream::new(client, Vec::new());

        server.write_all(&server_frame(0x05, b"?")).await.unwrap();
        let mut got = [0u8; 1];
        let err = ws.read_exact(&mut got).await.expect_err("не по протоколу");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
