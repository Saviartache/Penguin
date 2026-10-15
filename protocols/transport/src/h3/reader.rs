//! Чтение кадров HTTP/3 из потока QUIC.
//!
//! Один разборщик на все потоки — и на поток управления, и на потоки
//! запросов. Он поллинговый: из него собран `AsyncRead` над телом ответа,
//! а асинхронные обёртки ниже нужны тем, кто читает кадр целиком.

use std::future::poll_fn;
use std::task::{Context, Poll, ready};

use bytes::{Bytes, BytesMut};
use tokio::io::ReadBuf;

use super::code::{H3_EXCESSIVE_LOAD, H3_FRAME_ERROR};
use super::error::{H3Error, H3Result};
use super::frame::{self, FrameHeader};

/// Два варинта по восемь байт — самый длинный заголовок кадра.
const MAX_HEADER: usize = 16;

/// Кадры одного входящего потока.
#[derive(Debug)]
pub(super) struct FrameReader {
    recv: quinn::RecvStream,
    header: [u8; MAX_HEADER],
    header_len: usize,
    /// Сколько байт содержимого текущего кадра ещё не прочитано.
    remaining: u64,
}

impl FrameReader {
    /// Разборщик над потоком, с которого уже снят тип, если он был.
    pub(super) fn new(recv: quinn::RecvStream) -> Self {
        Self {
            recv,
            header: [0; MAX_HEADER],
            header_len: 0,
            remaining: 0,
        }
    }

    /// Поток QUIC под разборщиком.
    pub(super) fn stream(&mut self) -> &mut quinn::RecvStream {
        &mut self.recv
    }

    /// Сколько содержимого текущего кадра осталось.
    pub(super) fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Заголовок следующего кадра. `None` — поток кончился ровно на
    /// границе кадров. Содержимое прошлого кадра должно быть дочитано.
    pub(super) fn poll_header(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<H3Result<Option<FrameHeader>>> {
        debug_assert_eq!(self.remaining, 0, "содержимое прошлого кадра не дочитано");
        loop {
            if let Some((header, _)) = frame::decode_header(&self.header[..self.header_len]) {
                self.header_len = 0;
                self.remaining = header.len;
                return Poll::Ready(Ok(Some(header)));
            }
            // По байту: заголовок короткий, а лишнее прочитанное некуда
            // было бы деть.
            let mut byte = [0u8; 1];
            if ready!(self.recv.poll_read(cx, &mut byte)).map_err(read_error)? == 0 {
                return Poll::Ready(if self.header_len == 0 {
                    Ok(None)
                } else {
                    Err(truncated())
                });
            }
            self.header[self.header_len] = byte[0];
            self.header_len += 1;
        }
    }

    /// Читает содержимое текущего кадра в `buf`, не дальше его конца.
    pub(super) fn poll_payload(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<H3Result<()>> {
        let want = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buf.remaining());
        if want == 0 {
            return Poll::Ready(Ok(()));
        }
        let dst = buf.initialize_unfilled_to(want);
        let read = ready!(self.recv.poll_read(cx, dst)).map_err(read_error)?;
        if read == 0 {
            return Poll::Ready(Err(truncated()));
        }
        buf.advance(read);
        self.remaining -= read as u64;
        Poll::Ready(Ok(()))
    }

    /// Заголовок следующего кадра.
    pub(super) async fn header(&mut self) -> H3Result<Option<FrameHeader>> {
        poll_fn(|cx| self.poll_header(cx)).await
    }

    /// Содержимое текущего кадра целиком. Больше `limit` — ошибка.
    pub(super) async fn payload(&mut self, limit: usize) -> H3Result<Bytes> {
        let len = usize::try_from(self.remaining)
            .ok()
            .filter(|&len| len <= limit)
            .ok_or_else(|| H3Error::protocol(H3_EXCESSIVE_LOAD, "кадр больше предела"))?;
        let mut out = BytesMut::zeroed(len);
        let mut buf = ReadBuf::new(&mut out);
        while buf.remaining() > 0 {
            poll_fn(|cx| self.poll_payload(cx, &mut buf)).await?;
        }
        Ok(out.freeze())
    }

    /// Пропускает содержимое текущего кадра.
    pub(super) async fn skip(&mut self) -> H3Result<()> {
        let mut scratch = [0u8; 4096];
        while self.remaining > 0 {
            let mut buf = ReadBuf::new(&mut scratch);
            poll_fn(|cx| self.poll_payload(cx, &mut buf)).await?;
        }
        Ok(())
    }
}

/// Ошибка чтения QUIC на языке HTTP/3.
pub(super) fn read_error(err: quinn::ReadError) -> H3Error {
    match err {
        quinn::ReadError::Reset(code) => H3Error::Reset(code.into_inner()),
        err => H3Error::closed(err),
    }
}

fn truncated() -> H3Error {
    H3Error::protocol(H3_FRAME_ERROR, "поток кончился посреди кадра")
}
