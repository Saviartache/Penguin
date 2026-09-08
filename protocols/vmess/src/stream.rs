//! Поток VMess: снять заголовок ответа, дальше — кадр тела в обе стороны.
//!
//! Заголовок запроса отправляет [`crate::connector`] до того, как поток
//! появляется здесь; этот тип берёт на себя ровно то, что происходит после
//! него.
//!
//! # Заголовок ответа — лениво, как у VLESS
//!
//! Сервер шлёт свой заголовок не в ответ на наш, а вместе с первыми данными
//! (`buf.Copy(bodyReader, output, ...)` идёт параллельно с чтением заголовка
//! в одном соединении, эталон `v2fly/v2ray-core`). Прочитать его сразу после
//! отправки запроса нельзя — соединение зависло бы. Снимается он в первом же
//! [`AsyncRead::poll_read`], в две стадии: сначала блок длины (18 байт,
//! AEAD), потом сам заголовок (`длина + 16`, AEAD), и лишь потом байты
//! приложения.
//!
//! # Кадр тела — не у `zero`
//!
//! У `security = "zero"` кадра нет вовсе: после заголовка ответа это ровно
//! те байты, что отдало приложение на другом конце. У всех остальных шифров
//! (включая `none`) кадр есть — длина, кусок, может быть метка, может быть
//! дополнение ([`crate::frame::body`]) — и снимается или добавляется на
//! каждом чтении и записи.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::crypto::security::Wire;
use crate::crypto::session::Session;
use crate::error::VmessError;
use crate::frame::body::{BodyCipher, ChunkLength, MAX_PLAINTEXT};
use crate::frame::response;

/// Сколько байт брать из потока за раз, пока разбираем заголовок или кадр.
const READ_CHUNK: usize = 16 * 1024;

/// Сколько зашифрованного можно накопить, прежде чем слить в сокет.
const OUT_LIMIT: usize = 256 * 1024;

/// На чём сейчас стоит чтение.
#[derive(Clone, Copy)]
enum ReadState {
    /// Ждём 18 байт блока длины заголовка ответа.
    LengthBlock,
    /// Ждём `длина + 16` байт самого заголовка.
    PayloadBlock(usize),
    /// Заголовок снят, ждём длину следующего куска тела.
    ChunkLength,
    /// Ждём кусок известного размера.
    Chunk(ChunkLength),
    /// `security = "zero"`: кадра нет, всё, что приходит, — байты приложения.
    Raw,
    /// Кусок-терминатор пришёл: дальше по протоколу ничего не будет.
    Ended,
}

/// Поток VMess поверх соединения с сервером.
pub struct VmessStream<S> {
    io: S,
    recv: Option<BodyCipher>,
    send: Option<BodyCipher>,
    /// Ключи заголовка ответа — нужны только один раз, до [`ReadState::Raw`]
    /// или [`ReadState::ChunkLength`], но живут своими полями, а не внутри
    /// [`crate::crypto::session::Session`]: она уже потрачена на сборку
    /// `recv`/`send` к моменту, когда поток появляется.
    response_body_key: [u8; 16],
    response_body_iv: [u8; 16],
    response_header: u8,
    state: ReadState,
    incoming: BytesMut,
    ready: VecDeque<Bytes>,
    out: BytesMut,
    /// Терминатор тела уже поставлен в очередь на запись — `poll_shutdown`
    /// не должен добавлять его дважды.
    closing: bool,
}

impl<S> std::fmt::Debug for VmessStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessStream").finish()
    }
}

impl<S> VmessStream<S> {
    /// Оборачивает соединение, в которое уже отправлен заголовок запроса.
    pub fn new(io: S, session: &Session) -> Self {
        let framed = session.wire != Wire::Zero;
        Self {
            io,
            recv: framed.then(|| {
                BodyCipher::new(
                    session.wire,
                    &session.response_body_key,
                    &session.response_body_iv,
                )
            }),
            send: framed.then(|| {
                BodyCipher::new(
                    session.wire,
                    &session.request_body_key,
                    &session.request_body_iv,
                )
            }),
            response_body_key: session.response_body_key,
            response_body_iv: session.response_body_iv,
            response_header: session.response_header,
            state: ReadState::LengthBlock,
            incoming: BytesMut::new(),
            ready: VecDeque::new(),
            out: BytesMut::new(),
            closing: false,
        }
    }
}

impl<S: AsyncRead + Unpin> VmessStream<S> {
    /// Продвигает разбор на один шаг. `Ok(true)` — что-то разобралось,
    /// стоит попробовать ещё раз; `Ok(false)` — байт пока не хватает.
    fn take_step(&mut self) -> Result<bool, VmessError> {
        match self.state {
            ReadState::LengthBlock => {
                if self.incoming.len() < response::LENGTH_BLOCK_LEN {
                    return Ok(false);
                }
                let mut block: [u8; response::LENGTH_BLOCK_LEN] = self
                    .incoming
                    .split_to(response::LENGTH_BLOCK_LEN)
                    .as_ref()
                    .try_into()
                    .unwrap_or_else(|_| unreachable!("длина блока проверена выше"));
                // Ключи ответа не зависят от кадра тела и есть всегда — даже
                // у `zero`: заголовок ответа шифруется одинаково при любом
                // шифре тела (см. документ модуля).
                let len = response::open_length(
                    &self.response_body_key,
                    &self.response_body_iv,
                    &mut block,
                )?;
                self.state = ReadState::PayloadBlock(usize::from(len) + 16);
                Ok(true)
            }
            ReadState::PayloadBlock(len) => {
                if self.incoming.len() < len {
                    return Ok(false);
                }
                let mut block = self.incoming.split_to(len);
                response::open_payload(
                    &self.response_body_key,
                    &self.response_body_iv,
                    self.response_header,
                    &mut block,
                )?;
                self.state = if self.recv.is_some() {
                    ReadState::ChunkLength
                } else {
                    ReadState::Raw
                };
                Ok(true)
            }
            ReadState::ChunkLength => {
                if self.incoming.len() < 2 {
                    return Ok(false);
                }
                let field: [u8; 2] = self.incoming[..2]
                    .try_into()
                    .unwrap_or_else(|_| unreachable!("длина поля длины проверена выше"));
                let Some(recv) = self.recv.as_mut() else {
                    unreachable!("`ChunkLength` достижимо только когда `recv` собран")
                };
                match recv.decode_length(field)? {
                    Some(chunk) => {
                        self.incoming.advance(2);
                        self.state = ReadState::Chunk(chunk);
                    }
                    None => {
                        self.incoming.advance(2);
                        self.state = ReadState::Ended;
                    }
                }
                Ok(true)
            }
            ReadState::Chunk(chunk) => {
                if self.incoming.len() < chunk.on_wire {
                    return Ok(false);
                }
                let mut frame = self.incoming.split_to(chunk.on_wire);
                let Some(recv) = self.recv.as_mut() else {
                    unreachable!("`Chunk` достижимо только когда `recv` собран")
                };
                let plain_len = recv.open_chunk(&mut frame[..chunk.ciphertext])?.len();
                frame.truncate(plain_len);
                self.ready.push_back(frame.freeze());
                self.state = ReadState::ChunkLength;
                Ok(true)
            }
            ReadState::Raw | ReadState::Ended => Ok(false),
        }
    }

    fn mid_message(&self) -> bool {
        !matches!(
            self.state,
            ReadState::ChunkLength | ReadState::Raw | ReadState::Ended
        ) || !self.incoming.is_empty()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VmessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            if matches!(this.state, ReadState::Ended) {
                return Poll::Ready(Ok(()));
            }
            if let Some(front) = this.ready.front_mut() {
                let take = front.len().min(buf.remaining());
                buf.put_slice(&front[..take]);
                front.advance(take);
                if front.is_empty() {
                    this.ready.pop_front();
                }
                return Poll::Ready(Ok(()));
            }
            if matches!(this.state, ReadState::Raw) {
                // То, что уже накоплено при разборе заголовка (данные почти
                // всегда приходят с ним одним пакетом), обязано уйти первым
                // — иначе оно осталось бы лежать в `incoming` навсегда: без
                // кадра у `zero` эти байты никто больше не заберёт.
                if !this.incoming.is_empty() {
                    let take = this.incoming.len().min(buf.remaining());
                    buf.put_slice(&this.incoming[..take]);
                    this.incoming.advance(take);
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut this.io).poll_read(cx, buf);
            }

            match this.take_step() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(err) => return Poll::Ready(Err(as_io(err))),
            }

            let before = this.incoming.len();
            this.incoming.resize(before + READ_CHUNK, 0);
            let mut chunk = ReadBuf::new(&mut this.incoming[before..]);
            let result = Pin::new(&mut this.io).poll_read(cx, &mut chunk);
            let filled = chunk.filled().len();
            this.incoming.truncate(before + filled);

            match result {
                Poll::Ready(Ok(())) if filled == 0 => {
                    return Poll::Ready(if this.mid_message() {
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            VmessError::Disconnected(
                                "сервер закрыл поток, не ответив на запрос".to_owned(),
                            ),
                        ))
                    } else {
                        Ok(())
                    });
                }
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> VmessStream<S> {
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
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VmessStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.send.is_none() {
            return Pin::new(&mut this.io).poll_write(cx, buf);
        }

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

        let take = buf.len().min(MAX_PLAINTEXT);
        let sealed = {
            let Some(send) = this.send.as_mut() else {
                unreachable!("проверено выше: `send` собран для этого шифра")
            };
            send.seal_chunk(&buf[..take]).map_err(as_io)?
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

        if !this.closing
            && let Some(send) = this.send.as_mut()
        {
            this.closing = true;
            match send.seal_chunk(&[]) {
                Ok(terminator) => this.out.extend_from_slice(&terminator),
                Err(_) => {
                    // Не удалось собрать терминатор — закрываем как есть:
                    // сервер увидит обрыв TCP вместо явного сигнала, но
                    // соединение всё равно закроется.
                }
            }
        }

        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_shutdown(cx),
            other => other,
        }
    }
}

/// Ошибка протокола в языке, на котором говорят [`AsyncRead`] и [`AsyncWrite`].
fn as_io(err: VmessError) -> io::Error {
    match err {
        VmessError::Io(err) => err,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    /// То, что сервер отправил бы первым: заголовок ответа, потом кусок тела.
    fn server_wire(session: &Session, payload: &[u8]) -> Vec<u8> {
        let plain_header = [session.response_header, 0, 0, 0];
        let mut wire = seal_header(session, &plain_header);

        if session.wire != Wire::Zero {
            let mut body = BodyCipher::new(
                session.wire,
                &session.response_body_key,
                &session.response_body_iv,
            );
            wire.extend_from_slice(&body.seal_chunk(payload).expect("шифруется"));
        } else {
            wire.extend_from_slice(payload);
        }
        wire
    }

    /// Заголовок ответа, зашифрованный ровно так, как это делает сервер.
    fn seal_header(session: &Session, plain: &[u8]) -> Vec<u8> {
        use crate::crypto::aes_gcm;
        use crate::crypto::kdf::{kdf, kdf16};

        fn nonce12(base: &[u8; 16], label: &[u8]) -> [u8; 12] {
            let full = kdf(base, &[label]);
            let mut out = [0u8; 12];
            out.copy_from_slice(&full[..12]);
            out
        }

        let len_key = kdf16(&session.response_body_key, &[b"AEAD Resp Header Len Key"]);
        let len_nonce = nonce12(&session.response_body_iv, b"AEAD Resp Header Len IV");
        let sealed_len = aes_gcm::seal(
            &len_key,
            &len_nonce,
            &[],
            &u16::try_from(plain.len())
                .expect("короткий заголовок")
                .to_be_bytes(),
        )
        .expect("шифруется");

        let key = kdf16(&session.response_body_key, &[b"AEAD Resp Header Key"]);
        let nonce = nonce12(&session.response_body_iv, b"AEAD Resp Header IV");
        let sealed = aes_gcm::seal(&key, &nonce, &[], plain).expect("шифруется");

        let mut wire = sealed_len;
        wire.extend_from_slice(&sealed);
        wire
    }

    #[tokio::test]
    async fn the_response_header_is_stripped_and_the_chunk_decoded() {
        let session = Session::new(Wire::Aes128Gcm);
        let wire = server_wire(&session, b"payload");

        let (client, mut server) = duplex(8192);
        let mut stream = VmessStream::new(client, &session);
        server.write_all(&wire).await.expect("ушло");

        let mut got = [0u8; 7];
        stream.read_exact(&mut got).await.expect("пришло");
        assert_eq!(&got, b"payload");
    }

    #[tokio::test]
    async fn a_mismatched_response_header_byte_is_reported() {
        let session = Session::new(Wire::Aes128Gcm);
        // Заголовок расшифровался (ключи верны), но первый байт — не тот,
        // что отправил клиент: сервер отвечает не тому, кто спрашивал.
        let wrong_header = session.response_header.wrapping_add(1);
        let plain_header = [wrong_header, 0, 0, 0];
        let wire = seal_header(&session, &plain_header);

        let (client, mut server) = duplex(8192);
        let mut stream = VmessStream::new(client, &session);
        server.write_all(&wire).await.expect("ушло");

        let mut got = [0u8; 1];
        let err = stream
            .read_exact(&mut got)
            .await
            .expect_err("байт не совпал");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn zero_cipher_carries_the_header_but_not_a_frame() {
        let session = Session::new(Wire::Zero);
        let wire = server_wire(&session, b"raw-bytes");

        let (client, mut server) = duplex(8192);
        let mut stream = VmessStream::new(client, &session);
        server.write_all(&wire).await.expect("ушло");

        let mut got = [0u8; 9];
        stream.read_exact(&mut got).await.expect("пришло");
        assert_eq!(&got, b"raw-bytes");
    }

    #[tokio::test]
    async fn writes_come_out_as_a_frame_the_peer_can_decode() {
        let session = Session::new(Wire::Aes128Gcm);
        let (client, mut server) = duplex(8192);
        let mut stream = VmessStream::new(client, &session);

        stream.write_all(b"request").await.expect("ушло");
        stream.flush().await.expect("сброшено");

        let mut length_field = [0u8; 2];
        server
            .read_exact(&mut length_field)
            .await
            .expect("длина пришла");

        let mut send_side = BodyCipher::new(
            Wire::Aes128Gcm,
            &session.request_body_key,
            &session.request_body_iv,
        );
        let frame_len = send_side
            .decode_length(length_field)
            .expect("разбирается")
            .expect("не терминатор");

        let mut ciphertext = vec![0u8; frame_len.ciphertext];
        server
            .read_exact(&mut ciphertext)
            .await
            .expect("кусок пришёл");
        let plain = send_side
            .open_chunk(&mut ciphertext)
            .expect("расшифровался");
        assert_eq!(plain, b"request");
    }
}
