//! Поток приложения поверх уже отправленного заголовка Brook.
//!
//! К моменту, когда заводится [`BrookStream`], рукопожатие уже прошло:
//! собственный нонс ушёл на провод, первый кусок с меткой времени и адресом
//! отправлен, чужой нонс получен. Здесь остаётся то, что видит приложение, —
//! чтение и запись обычных байт, кусками кадра ([`crate::frame::tcp`]).

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::BrookError;
use crate::frame::cipher::{Cipher, sealed_len};
use crate::frame::tcp::{self, LENGTH_FRAME, MAX_PAYLOAD};

/// Сколько байт брать из сокета за раз.
const READ_CHUNK: usize = 16 * 1024;

/// Сколько зашифрованного копить, прежде чем перестать принимать новое.
const OUT_LIMIT: usize = 256 * 1024;

/// Поток приложения через уже открытое и опознанное соединение Brook.
pub struct BrookStream<S> {
    io: S,
    send: Cipher,
    recv: Cipher,
    /// Длина следующего куска данных, если она уже расшифрована.
    expect: Option<usize>,
    /// Зашифрованное, ещё не ушедшее в сокет.
    out: BytesMut,
    /// Сырое из сокета, ещё не разобранное.
    incoming: BytesMut,
    /// Расшифрованные куски, ещё не отданные читателю.
    ready: VecDeque<BytesMut>,
}

impl<S> std::fmt::Debug for BrookStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrookStream")
            .field("ready", &self.ready.len())
            .field("out", &self.out.len())
            .finish()
    }
}

impl<S> BrookStream<S> {
    /// Оборачивает соединение вокруг уже готовых шифров направлений.
    pub fn new(io: S, send: Cipher, recv: Cipher) -> Self {
        Self {
            io,
            send,
            recv,
            expect: None,
            out: BytesMut::new(),
            incoming: BytesMut::new(),
            ready: VecDeque::new(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> BrookStream<S> {
    /// Дописывает в сокет всё, что накопилось.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.out.is_empty() {
            match Pin::new(&mut self.io).poll_write(cx, &self.out) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(written)) => self.out.advance(written),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Забирает из накопленного столько, сколько получится: длину, потом кусок.
    ///
    /// `Ok(false)` — байт пока не хватает.
    fn take_step(&mut self) -> Result<bool, BrookError> {
        match self.expect {
            None => {
                if self.incoming.len() < LENGTH_FRAME {
                    return Ok(false);
                }
                let mut frame = self.incoming.split_to(LENGTH_FRAME);
                let length = usize::from(tcp::open_length(&mut self.recv, &mut frame)?);

                // Больше своего же предела на кусок сервер эталона никогда не
                // пришлёт — у него тот же буфер в 2048 байт. Значение за этой
                // границей говорит не о большом кадре, а о том, что поток
                // разъехался с форматом.
                if length > MAX_PAYLOAD {
                    return Err(BrookError::malformed(format!(
                        "кусок в {length} байт длиннее, чем шлёт настоящий сервер"
                    )));
                }
                self.expect = Some(length);
                Ok(true)
            }
            Some(length) => {
                if self.incoming.len() < sealed_len(length) {
                    return Ok(false);
                }
                let mut frame = self.incoming.split_to(sealed_len(length));
                let plain = self.recv.open(&mut frame)?;
                frame.truncate(plain);
                self.ready.push_back(frame);
                self.expect = None;
                Ok(true)
            }
        }
    }

    /// Ждём ли мы сейчас продолжения того, что уже начали читать.
    fn mid_message(&self) -> bool {
        self.expect.is_some() || !self.incoming.is_empty()
    }

    /// Двигает разбор, пока не появится кусок или не кончится поток.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            if !self.ready.is_empty() {
                return Poll::Ready(Ok(true));
            }

            match self.take_step() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(err) => return Poll::Ready(Err(as_io(err))),
            }

            let before = self.incoming.len();
            self.incoming.resize(before + READ_CHUNK, 0);
            let mut chunk = ReadBuf::new(&mut self.incoming[before..]);

            let result = Pin::new(&mut self.io).poll_read(cx, &mut chunk);
            let filled = chunk.filled().len();
            self.incoming.truncate(before + filled);

            match result {
                Poll::Ready(Ok(())) if filled == 0 => {
                    // Оборванный на середине кусок — потерянные данные, и
                    // отдать их как обычный конец потока значит показать
                    // неполный ответ полным.
                    return Poll::Ready(if self.mid_message() {
                        Err(io::Error::from(io::ErrorKind::UnexpectedEof))
                    } else {
                        Ok(false)
                    });
                }
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for BrookStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        match this.poll_ready(cx) {
            Poll::Ready(Ok(true)) => {}
            Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        let Some(front) = this.ready.front_mut() else {
            return Poll::Ready(Ok(()));
        };
        let take = front.len().min(buf.remaining());
        buf.put_slice(&front[..take]);
        front.advance(take);
        if front.is_empty() {
            this.ready.pop_front();
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for BrookStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.out.len() >= OUT_LIMIT {
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Не больше предела, какой примет настоящий сервер: он читает ровно
        // 2048 байт на кусок и ни байтом больше.
        let take = buf.len().min(MAX_PAYLOAD);
        let sealed = match tcp::seal_fragment(&mut this.send, &buf[..take]) {
            Ok(sealed) => sealed,
            Err(err) => return Poll::Ready(Err(as_io(err))),
        };
        this.out.extend_from_slice(&sealed);

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
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_shutdown(cx),
            other => other,
        }
    }
}

/// Ошибка в языке, на котором говорят [`AsyncRead`] и [`AsyncWrite`].
fn as_io(err: BrookError) -> io::Error {
    match err {
        BrookError::Io(err) => err,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;
    use crate::frame::nonce::Nonce;

    fn cipher(nonce: Nonce) -> Cipher {
        Cipher::new(b"secret", nonce).expect("собирается")
    }

    /// Пара «наш поток, поток собеседника с обратными шифрами».
    ///
    /// Направление А шифрует нонсом `[1;12]` и расшифровывает нонсом
    /// `[2;12]`; у направления Б — наоборот. Так и устроены `send`/`recv` на
    /// двух концах настоящего соединения: у каждой стороны свой нонс на
    /// отправку, и он же — чужой нонс на приём у собеседника.
    fn pair() -> (BrookStream<DuplexStream>, BrookStream<DuplexStream>) {
        let (ours, theirs) = tokio::io::duplex(1024 * 1024);
        let a = BrookStream::new(ours, cipher([1u8; 12]), cipher([2u8; 12]));
        let b = BrookStream::new(theirs, cipher([2u8; 12]), cipher([1u8; 12]));
        (a, b)
    }

    #[tokio::test]
    async fn what_one_side_writes_the_other_reads() {
        let (mut client, mut server) = pair();
        client.write_all(b"payload").await.expect("пишется");
        client.flush().await.expect("уходит");

        let mut got = [0u8; 7];
        server.read_exact(&mut got).await.expect("читается");
        assert_eq!(&got, b"payload");
    }

    #[tokio::test]
    async fn both_directions_work_independently() {
        let (mut client, mut server) = pair();
        client.write_all(b"to-server").await.expect("пишется");
        server.write_all(b"to-client").await.expect("пишется");
        client.flush().await.expect("уходит");
        server.flush().await.expect("уходит");

        let mut from_client = [0u8; 9];
        server.read_exact(&mut from_client).await.expect("читается");
        assert_eq!(&from_client, b"to-server");

        let mut from_server = [0u8; 9];
        client.read_exact(&mut from_server).await.expect("читается");
        assert_eq!(&from_server, b"to-client");
    }

    #[tokio::test]
    async fn a_long_write_is_cut_at_the_server_buffer_size() {
        let (mut client, mut server) = pair();
        let payload = vec![7u8; MAX_PAYLOAD + 100];

        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.expect("пишется");
            client.flush().await.expect("уходит");
        });

        let mut got = vec![0u8; MAX_PAYLOAD + 100];
        server.read_exact(&mut got).await.expect("читается");
        assert!(got.iter().all(|byte| *byte == 7));
        writer.await.expect("задача");
    }

    #[tokio::test]
    async fn a_mismatched_nonce_is_an_error_not_a_panic() {
        // `server` здесь ждёт нонс `[9;12]` от собеседника, а получает поток,
        // зашифрованный нонсом `[1;12]`, — то же самое видел бы клиент,
        // подключившийся не тем паролем.
        let (ours, theirs) = tokio::io::duplex(1024 * 1024);
        let mut client = BrookStream::new(ours, cipher([1u8; 12]), cipher([2u8; 12]));
        let mut server = BrookStream::new(theirs, cipher([2u8; 12]), cipher([9u8; 12]));

        client.write_all(b"payload").await.expect("пишется");
        client.flush().await.expect("уходит");

        let mut got = [0u8; 7];
        let err = server.read_exact(&mut got).await.expect_err("метка не та");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_stream_cut_mid_chunk_is_an_error() {
        let (ours, mut raw) = tokio::io::duplex(1024 * 1024);
        let mut client = BrookStream::new(ours, cipher([1u8; 12]), cipher([2u8; 12]));
        client.write_all(b"payload").await.expect("пишется");
        client.flush().await.expect("уходит");

        let mut wire = vec![0u8; LENGTH_FRAME + sealed_len(7)];
        raw.read_exact(&mut wire).await.expect("читается");

        let (theirs, mut feed) = tokio::io::duplex(1024 * 1024);
        let mut server = BrookStream::new(theirs, cipher([2u8; 12]), cipher([1u8; 12]));
        feed.write_all(&wire[..wire.len() - 3])
            .await
            .expect("пишется");
        drop(feed);

        let mut got = Vec::new();
        let err = server.read_to_end(&mut got).await.expect_err("обрыв");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
