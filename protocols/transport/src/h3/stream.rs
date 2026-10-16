//! Поток запроса: заголовки ответа и тело как `AsyncRead`/`AsyncWrite` (кадры `DATA` снимаются и надеваются).

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::code::{H3_FRAME_UNEXPECTED, H3_ID_ERROR, H3_MESSAGE_ERROR, H3_REQUEST_CANCELLED};
use super::connection::{close_with, var_int};
use super::error::{H3Error, H3Result};
use super::frame::{self, FrameHeader};
use super::message::Response;
use super::qpack::field;
use super::reader::FrameReader;

/// Наибольшее тело кадра `DATA` при записи через `AsyncWrite`.
const MAX_DATA_FRAME: usize = 16 * 1024;

/// Поток запроса целиком.
#[derive(Debug)]
pub struct RequestStream {
    send: SendStream,
    recv: RecvStream,
}

impl RequestStream {
    pub(super) fn new(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        quic: quinn::Connection,
        limit: usize,
    ) -> Self {
        Self {
            send: SendStream {
                send,
                frame: Vec::new(),
                sent: 0,
                body_len: 0,
            },
            recv: RecvStream {
                reader: FrameReader::new(recv),
                quic,
                limit,
                in_data: false,
                done: false,
            },
        }
    }

    /// Номер потока QUIC — по нему датаграммы HTTP/3 находят свой запрос.
    pub fn id(&self) -> u64 {
        self.send.id()
    }

    /// Ждёт окончательный ответ.
    pub async fn response(&mut self) -> H3Result<Response> {
        self.recv.response().await
    }

    /// Закрывает отправку: тела больше не будет.
    pub fn finish(&mut self) -> H3Result<()> {
        self.send.finish()
    }

    /// Делит поток на отправку и приём.
    pub fn split(self) -> (SendStream, RecvStream) {
        (self.send, self.recv)
    }
}

impl AsyncRead for RequestStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for RequestStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().send).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}

/// Отправка: тело кадрами `DATA`.
#[derive(Debug)]
pub struct SendStream {
    send: quinn::SendStream,
    /// Буфер кадра, переиспользуется; `frame[sent..]` ещё не ушло в QUIC.
    frame: Vec<u8>,
    sent: usize,
    /// Длина тела в буфере кадра.
    body_len: usize,
}

impl SendStream {
    /// Номер потока QUIC.
    pub fn id(&self) -> u64 {
        self.send.id().into()
    }

    /// Отправляет кусок тела одним кадром `DATA`.
    pub async fn send_data(&mut self, data: &[u8]) -> H3Result<()> {
        poll_fn(|cx| self.poll_drain(cx)).await?;
        self.fill(data);
        poll_fn(|cx| self.poll_drain(cx)).await
    }

    /// Закрывает отправку штатно.
    pub fn finish(&mut self) -> H3Result<()> {
        self.send.finish().map_err(H3Error::closed)
    }

    /// Собирает кадр `DATA` в переиспользуемом буфере (прошлый кадр дописан).
    fn fill(&mut self, data: &[u8]) {
        self.frame.clear();
        self.sent = 0;
        frame::encode_header(frame::DATA, data.len() as u64, &mut self.frame);
        self.frame.extend_from_slice(data);
        self.body_len = data.len();
    }

    /// Дописывает в QUIC остаток собранного кадра.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<H3Result<()>> {
        while self.sent < self.frame.len() {
            let written = ready!(Pin::new(&mut self.send).poll_write(cx, &self.frame[self.sent..]))
                .map_err(write_error)?;
            self.sent += written;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.sent == this.frame.len() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            this.fill(&buf[..buf.len().min(MAX_DATA_FRAME)]);
        }
        // Повтор после `Pending` приходит с теми же байтами
        ready!(this.poll_drain(cx))?;
        Poll::Ready(Ok(this.body_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_drain(cx).map_err(io::Error::from)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        let _ = this.send.finish();
        Poll::Ready(Ok(()))
    }
}

/// Приём: заголовки ответа, затем тело.
#[derive(Debug)]
pub struct RecvStream {
    reader: FrameReader,
    /// Для закрытия соединения при нарушении протокола.
    quic: quinn::Connection,
    /// Предел блока полей ответа.
    limit: usize,
    /// Читается тело кадра `DATA`, а не пропускается чужой кадр.
    in_data: bool,
    done: bool,
}

impl RecvStream {
    /// Ждёт окончательный ответ; промежуточные `1xx` пропускаются.
    pub async fn response(&mut self) -> H3Result<Response> {
        let result = self.read_response().await;
        if let Err(err) = &result {
            self.fail(err);
        }
        result
    }

    async fn read_response(&mut self) -> H3Result<Response> {
        loop {
            let header = self
                .reader
                .header()
                .await?
                .ok_or_else(|| H3Error::Closed("поток закрыт до ответа".to_owned()))?;
            match header.kind {
                frame::HEADERS => {
                    let block = self.reader.payload(self.limit).await?;
                    let fields = field::decode(&block, self.limit)?;
                    let response = Response::from_fields(fields)?;
                    if !(100..200).contains(&response.status()) {
                        return Ok(response);
                    }
                }
                frame::DATA => {
                    return Err(H3Error::protocol(
                        H3_FRAME_UNEXPECTED,
                        "DATA раньше заголовков ответа",
                    ));
                }
                kind => {
                    check_request_frame(kind)?;
                    self.reader.skip().await?;
                }
            }
        }
    }

    /// Нарушение протокола закрывает соединение, неверное сообщение — только поток.
    fn fail(&mut self, err: &H3Error) {
        match err {
            H3Error::Protocol { code, reason } => close_with(&self.quic, *code, reason),
            H3Error::Message(_) => {
                let _ = self.reader.stream().stop(var_int(H3_MESSAGE_ERROR));
            }
            _ => {}
        }
    }

    /// Следующий кусок тела. `Ok(false)` — тело кончилось.
    fn poll_body(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<H3Result<bool>> {
        loop {
            if self.reader.remaining() > 0 {
                if self.in_data {
                    ready!(self.reader.poll_payload(cx, buf))?;
                    return Poll::Ready(Ok(true));
                }
                let mut scratch = [0u8; 1024];
                let mut skip = ReadBuf::new(&mut scratch);
                ready!(self.reader.poll_payload(cx, &mut skip))?;
                continue;
            }
            let Some(FrameHeader { kind, .. }) = ready!(self.reader.poll_header(cx))? else {
                return Poll::Ready(Ok(false));
            };
            self.in_data = kind == frame::DATA;
            if kind != frame::DATA && kind != frame::HEADERS {
                check_request_frame(kind)?;
            }
        }
    }
}

impl AsyncRead for RecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.done || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match ready!(this.poll_body(cx, buf)) {
            Ok(true) => Poll::Ready(Ok(())),
            Ok(false) => {
                this.done = true;
                Poll::Ready(Ok(()))
            }
            Err(err) => {
                this.fail(&err);
                Poll::Ready(Err(err.into()))
            }
        }
    }
}

impl Drop for RecvStream {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.reader.stream().stop(var_int(H3_REQUEST_CANCELLED));
        }
    }
}

/// Кадры, которым нечего делать на потоке запроса (RFC 9114, §7.2).
fn check_request_frame(kind: u64) -> H3Result<()> {
    match kind {
        frame::CANCEL_PUSH | frame::SETTINGS | frame::GOAWAY | frame::MAX_PUSH_ID => {
            Err(H3Error::protocol(
                H3_FRAME_UNEXPECTED,
                format!("кадр {kind:#x} на потоке запроса"),
            ))
        }
        kind if frame::is_reserved_http2(kind) => Err(H3Error::protocol(
            H3_FRAME_UNEXPECTED,
            format!("кадр HTTP/2 {kind:#x}"),
        )),
        frame::PUSH_PROMISE => Err(H3Error::protocol(
            H3_ID_ERROR,
            "PUSH_PROMISE без MAX_PUSH_ID",
        )),
        _ => Ok(()),
    }
}

/// Ошибка записи QUIC на языке HTTP/3.
pub(super) fn write_error(err: quinn::WriteError) -> H3Error {
    match err {
        quinn::WriteError::Stopped(code) => H3Error::Reset(code.into_inner()),
        err => H3Error::closed(err),
    }
}
