//! Дополнение байтового потока — `NaivePaddingSocket`/`NaivePaddingFramer`
//! эталона (`naive_padding_socket.cc`, `naive_padding_framer.h`).
//!
//! ```text
//!  ──► [длина: u16 BE] [дополнение: u8] [данные] [нули: `дополнение` байт] ...
//! ```
//!
//! Обрамляются первые 8 чтений и первые 8 записей (`kFirstPaddings`), счётчики
//! раздельные. Длина дополнения клиента равномерна в `[0, 255]`: особый случай
//! `[255 - длина, 255]` в эталоне только у `direction = kServer`
//! (`naive_padding_socket.cc`, `WritePaddingV1`); чтению он не важен.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use penguin_proto::random;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::padding::PaddingType;

/// Сколько первых операций каждого вида обрамляется (`kFirstPaddings`).
const FIRST_FRAMES: usize = 8;

/// Наибольшая длина дополнения: оно пишется одним байтом (`max_padding_size()`).
const MAX_PADDING: u8 = u8::MAX;

/// Длина заголовка кадра: `u16` длины данных плюс `u8` длины дополнения.
const HEADER_LEN: usize = 2 + 1;

/// Сколько байт брать из сокета за раз при разборе кадров.
const READ_CHUNK: usize = 16 * 1024;

/// Поток с дополнением первых кадров; при [`PaddingType::None`] — прозрачный.
pub struct PaddedStream<S> {
    inner: S,
    mode: PaddingType,

    write_frames: usize,
    /// Обрамлённое, ещё не ушедшее в сокет.
    out: BytesMut,

    read_frames: usize,
    /// Сырое из сокета, ещё не разобранное.
    incoming: BytesMut,
    /// Разобранные данные кадра, ещё не отданные читателю.
    pending: BytesMut,
}

impl<S> std::fmt::Debug for PaddedStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaddedStream")
            .field("mode", &self.mode)
            .field("write_frames", &self.write_frames)
            .field("read_frames", &self.read_frames)
            .finish()
    }
}

impl<S> PaddedStream<S> {
    /// Оборачивает туннель; `mode` — результат [`crate::padding::negotiate`].
    pub fn new(inner: S, mode: PaddingType) -> Self {
        Self {
            inner,
            mode,
            write_frames: 0,
            out: BytesMut::new(),
            read_frames: 0,
            incoming: BytesMut::new(),
            pending: BytesMut::new(),
        }
    }

    /// Ещё дополняем запись — очередной вызов `poll_write` обязан обрамить.
    fn still_padding_writes(&self) -> bool {
        matches!(self.mode, PaddingType::Variant1) && self.write_frames < FIRST_FRAMES
    }

    /// Ещё дополняем чтение — очередной кадр обязан разбираться.
    fn still_padding_reads(&self) -> bool {
        matches!(self.mode, PaddingType::Variant1) && self.read_frames < FIRST_FRAMES
    }
}

impl<S: AsyncWrite + Unpin> PaddedStream<S> {
    /// Дописывает в сокет всё, что накопилось.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.out.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.out) {
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
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PaddedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if !this.out.is_empty() {
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if this.still_padding_writes() {
            let take = buf.len().min(u16::MAX as usize);
            let padding_len = random::range(0..u64::from(MAX_PADDING) + 1) as u8;

            this.out
                .reserve(HEADER_LEN + take + usize::from(padding_len));
            this.out.extend_from_slice(&(take as u16).to_be_bytes());
            this.out.extend_from_slice(&[padding_len]);
            this.out.extend_from_slice(&buf[..take]);
            this.out
                .resize(this.out.len() + usize::from(padding_len), 0);
            this.write_frames += 1;

            let _ = this.poll_drain(cx);
            return Poll::Ready(Ok(take));
        }

        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

impl<S: AsyncRead + Unpin> PaddedStream<S> {
    /// Забирает из накопленного один кадр, если он пришёл целиком.
    ///
    /// Данные кадра без нулевого хвоста; `None` — кадр пришёл не весь.
    fn take_frame(&mut self) -> Option<BytesMut> {
        let header = self.incoming.first_chunk::<HEADER_LEN>()?;
        let payload_len = usize::from(u16::from_be_bytes([header[0], header[1]]));
        let padding_len = usize::from(header[2]);

        let total = HEADER_LEN + payload_len + padding_len;
        if self.incoming.len() < total {
            return None;
        }

        let mut frame = self.incoming.split_to(total);
        frame.advance(HEADER_LEN);
        frame.truncate(payload_len);
        Some(frame)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PaddedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            if !this.pending.is_empty() {
                let take = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending[..take]);
                this.pending.advance(take);
                return Poll::Ready(Ok(()));
            }

            if !this.still_padding_reads() {
                if !this.incoming.is_empty() {
                    let take = this.incoming.len().min(buf.remaining());
                    buf.put_slice(&this.incoming[..take]);
                    this.incoming.advance(take);
                    return Poll::Ready(Ok(()));
                }
                return AsyncRead::poll_read(Pin::new(&mut this.inner), cx, buf);
            }

            if let Some(frame) = this.take_frame() {
                this.pending = frame;
                this.read_frames += 1;
                continue;
            }

            let before = this.incoming.len();
            this.incoming.resize(before + READ_CHUNK, 0);
            let mut chunk = ReadBuf::new(&mut this.incoming[before..]);

            let result = Pin::new(&mut this.inner).poll_read(cx, &mut chunk);
            let filled = chunk.filled().len();
            this.incoming.truncate(before + filled);

            match result {
                Poll::Ready(Ok(())) if filled == 0 => {
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

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    use super::*;

    fn pair(mode: PaddingType) -> (PaddedStream<DuplexStream>, DuplexStream) {
        let (ours, theirs) = duplex(64 * 1024);
        (PaddedStream::new(ours, mode), theirs)
    }

    /// Кадр в формате эталона, для проверки со стороны "сервера".
    fn frame(payload: &[u8], padding_len: u8) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.push(padding_len);
        out.extend_from_slice(payload);
        out.extend(std::iter::repeat_n(0u8, usize::from(padding_len)));
        out
    }

    #[tokio::test]
    async fn a_write_without_padding_negotiated_goes_out_as_is() {
        let (mut stream, mut peer) = pair(PaddingType::None);
        stream.write_all(b"hello").await.expect("пишется");
        stream.flush().await.expect("уходит");

        let mut got = [0u8; 5];
        peer.read_exact(&mut got).await.expect("читается");
        assert_eq!(&got, b"hello");
    }

    #[tokio::test]
    async fn the_first_write_is_framed_and_the_frame_is_well_formed() {
        let (mut stream, mut peer) = pair(PaddingType::Variant1);
        stream.write_all(b"hi").await.expect("пишется");
        stream.flush().await.expect("уходит");

        let mut header = [0u8; HEADER_LEN];
        peer.read_exact(&mut header).await.expect("заголовок");
        let payload_len = u16::from_be_bytes([header[0], header[1]]);
        let padding_len = header[2];
        assert_eq!(payload_len, 2);

        let mut rest = vec![0u8; usize::from(payload_len) + usize::from(padding_len)];
        peer.read_exact(&mut rest).await.expect("тело кадра");
        assert_eq!(&rest[..2], b"hi");
        assert!(rest[2..].iter().all(|&b| b == 0), "хвост не из нулей");
    }

    #[tokio::test]
    async fn a_ninth_write_is_not_framed() {
        let (mut stream, mut peer) = pair(PaddingType::Variant1);

        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            let mut collected = Vec::new();
            while collected.len() < 8192 {
                match peer.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => collected.extend_from_slice(&buf[..n]),
                    Err(_) => break,
                }
            }
            collected
        });

        for _ in 0..8 {
            stream.write_all(b"a").await.expect("пишется");
        }
        stream.write_all(b"bbbbbbbb").await.expect("пишется");
        stream.flush().await.expect("уходит");
        drop(stream);

        let wire = reader.await.expect("задача");
        assert!(
            wire.windows(8).any(|w| w == b"bbbbbbbb"),
            "девятая запись оказалась обрамлена: {wire:?}"
        );
    }

    #[tokio::test]
    async fn reading_strips_the_padding_for_the_first_frames() {
        let (mut stream, mut peer) = pair(PaddingType::Variant1);
        peer.write_all(&frame(b"first", 10)).await.expect("пишется");
        peer.write_all(&frame(b"second", 0)).await.expect("пишется");

        let mut got = [0u8; 5];
        stream.read_exact(&mut got).await.expect("читается");
        assert_eq!(&got, b"first");

        let mut got = [0u8; 6];
        stream.read_exact(&mut got).await.expect("читается");
        assert_eq!(&got, b"second");
    }

    #[tokio::test]
    async fn a_frame_split_across_reads_is_still_assembled() {
        let (mut stream, mut peer) = pair(PaddingType::Variant1);
        let wire = frame(b"payload", 4);

        let writer = tokio::spawn(async move {
            for byte in wire {
                peer.write_all(&[byte]).await.expect("пишется");
                peer.flush().await.expect("уходит");
            }
        });

        let mut got = [0u8; 7];
        stream.read_exact(&mut got).await.expect("читается");
        assert_eq!(&got, b"payload");
        writer.await.expect("задача");
    }

    #[tokio::test]
    async fn after_eight_frames_reading_is_raw() {
        let (mut stream, mut peer) = pair(PaddingType::Variant1);

        let writer = tokio::spawn(async move {
            for _ in 0..8 {
                peer.write_all(&frame(b"x", 0)).await.expect("пишется");
            }
            peer.write_all(b"raw-data").await.expect("пишется");
        });

        let mut got = [0u8; 8];
        for _ in 0..8 {
            stream.read_exact(&mut got[..1]).await.expect("читается");
            assert_eq!(&got[..1], b"x");
        }

        let mut tail = [0u8; 8];
        stream.read_exact(&mut tail).await.expect("читается");
        assert_eq!(&tail, b"raw-data");
        writer.await.expect("задача");
    }

    #[tokio::test]
    async fn no_padding_negotiated_means_reading_is_raw_from_the_start() {
        let (mut stream, mut peer) = pair(PaddingType::None);
        peer.write_all(b"plain").await.expect("пишется");

        let mut got = [0u8; 5];
        stream.read_exact(&mut got).await.expect("читается");
        assert_eq!(&got, b"plain");
    }
}
