//! Поток, зашифрованный кусками.
//!
//! ```text
//!  ──► [соль] [длина+метка] [кусок+метка] [длина+метка] [кусок+метка] ...
//!       ^^^^^^
//!       открытым текстом, один раз в начале
//! ```
//!
//! # Почему длина шифруется отдельным куском
//!
//! Внутри — поток байт без границ, а AEAD работает сообщениями: расшифровать
//! половину сообщения нельзя. Значит, до того как читать кусок, надо знать
//! его длину, — и она приезжает своим маленьким сообщением на две байта.
//! Каждое из двух тратит свой шаг счётчика.
//!
//! Отсюда правило, которое легко нарушить: длину, уже расшифрованную,
//! **нельзя расшифровать заново**. Счётчик сдвинут, и вторая попытка даст не
//! ту же длину, а разъехавшийся поток. Поэтому прочитанная длина живёт в
//! поле `expect` до тех пор, пока не придёт весь кусок.
//!
//! # Два взгляда на одно и то же
//!
//! Наружу поток смотрит двумя способами. Обычный — [`AsyncRead`] и
//! [`AsyncWrite`]: байты без границ, как их и ждёт всё остальное. Второй —
//! [`ChunkStream::read_chunk`] и [`ChunkStream::write_chunk`]: кусок целиком.
//!
//! Второй нужен там, где граница куска что-то значит. У Snell датаграмма UDP
//! — это ровно один кусок, и склеить две в одну означало бы отдать
//! приложению не ту датаграмму. Байтовому потоку граница не нужна, и он её не
//! видит; но потерять её нельзя, поэтому расшифрованное лежит очередью
//! кусков, а не одним буфером.
//!
//! # Предел куска
//!
//! Длина пишется двумя байтами, но старшие два бита протокол оставляет себе:
//! кусок не бывает длиннее [`MAX_CHUNK`]. Собеседник, объявивший больше, —
//! это не тот протокол, и продолжать после такого нечего.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::aead::algorithm::TAG_LEN;
use crate::aead::cipher::{Cipher, sealed_len};
use crate::aead::keying::Keying;
use crate::error::{TransportError, TransportResult};

/// Наибольший кусок, какой позволяет обрамление.
pub const MAX_CHUNK: usize = 0x3FFF;

/// Сколько байт занимает зашифрованная длина: два байта и метка.
const LENGTH_FRAME: usize = 2 + TAG_LEN;

/// Сколько байт брать из сокета за раз.
const READ_CHUNK: usize = 16 * 1024;

/// Сколько зашифрованного можно накопить, прежде чем перестать принимать новое.
const OUT_LIMIT: usize = 256 * 1024;

/// Поток, зашифрованный кусками, поверх обычного соединения.
pub struct ChunkStream<S> {
    io: S,
    keying: Keying,
    /// Шифр на отправку. Готов сразу: соль мы бросили сами.
    send: Cipher,
    /// Шифр на приём. `None`, пока собеседник не прислал свою соль.
    recv: Option<Cipher>,
    /// Длина куска, уже расшифрованная и ещё не использованная.
    expect: Option<usize>,
    /// Зашифрованное, ещё не ушедшее в сокет.
    out: BytesMut,
    /// Сырое из сокета, ещё не разобранное.
    incoming: BytesMut,
    /// Расшифрованные куски, ещё не отданные читателю.
    ready: VecDeque<BytesMut>,
}

impl<S> std::fmt::Debug for ChunkStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkStream")
            .field("keying", &self.keying)
            .field("ready", &self.ready.len())
            .field("out", &self.out.len())
            .finish()
    }
}

impl<S> ChunkStream<S> {
    /// Оборачивает соединение, в которое уже отправлена своя соль.
    pub fn new(io: S, keying: Keying, send: Cipher) -> Self {
        Self {
            io,
            keying,
            send,
            recv: None,
            expect: None,
            out: BytesMut::new(),
            incoming: BytesMut::new(),
            ready: VecDeque::new(),
        }
    }

    /// Шифр на отправку: им же закрывается первый кусок с заголовком.
    pub fn sender(&mut self) -> &mut Cipher {
        &mut self.send
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> ChunkStream<S> {
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

    /// Забирает из накопленного столько, сколько получится: соль, длину, кусок.
    ///
    /// `Ok(false)` — байт пока не хватает.
    fn take_step(&mut self) -> TransportResult<bool> {
        if self.recv.is_none() {
            let salt_len = self.keying.salt_len();
            if self.incoming.len() < salt_len {
                return Ok(false);
            }
            let salt = self.incoming.split_to(salt_len);
            self.recv = Some(self.keying.cipher(&salt)?);
            return Ok(true);
        }

        let Some(recv) = self.recv.as_mut() else {
            return Ok(false);
        };

        match self.expect {
            None => {
                if self.incoming.len() < LENGTH_FRAME {
                    return Ok(false);
                }
                let mut frame = self.incoming.split_to(LENGTH_FRAME);
                let plain = recv.open(&mut frame)?;
                let Some(raw) = frame.get(..plain).and_then(<[u8]>::first_chunk::<2>) else {
                    return Err(TransportError::malformed("длина куска не на месте"));
                };

                let length = usize::from(u16::from_be_bytes(*raw));
                // Ноль означал бы кусок без данных, то есть шаг счётчика
                // впустую; больше предела — что на том конце не тот протокол.
                if length == 0 || length > MAX_CHUNK {
                    return Err(TransportError::malformed(format!(
                        "кусок в {length} байт: обрамление такого не допускает"
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
                let plain = recv.open(&mut frame)?;
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
    ///
    /// `Ok(false)` — поток кончился, и кончился чисто.
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
                    // Оборванный на середине кусок — это потерянные данные, и
                    // отдать их наверх как обычный конец потока значит
                    // показать приложению неполный ответ как полный.
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

    /// Читает **один кусок целиком**.
    ///
    /// `Ok(None)` — поток кончился. Нужен там, где граница куска что-то
    /// значит: у Snell один кусок — это одна датаграмма UDP.
    pub async fn read_chunk(&mut self) -> io::Result<Option<BytesMut>> {
        std::future::poll_fn(|cx| match self.poll_ready(cx) {
            Poll::Ready(Ok(true)) => Poll::Ready(Ok(self.ready.pop_front())),
            Poll::Ready(Ok(false)) => Poll::Ready(Ok(None)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        })
        .await
    }

    /// Отправляет **один кусок целиком** и доводит его до сокета.
    pub async fn write_chunk(&mut self, payload: &[u8]) -> io::Result<()> {
        let sealed = seal_chunk(&mut self.send, payload).map_err(as_io)?;
        self.out.extend_from_slice(&sealed);

        std::future::poll_fn(|cx| self.poll_drain(cx)).await?;
        std::future::poll_fn(|cx| Pin::new(&mut self.io).poll_flush(cx)).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ChunkStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        match this.poll_ready(cx) {
            Poll::Ready(Ok(true)) => {}
            // Конец потока: ноль прочитанных байт и есть его признак.
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ChunkStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Накопилось слишком много — сначала отдать это в сокет. Иначе
        // медленный сервер набивал бы память со скоростью записи приложения.
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

        let take = buf.len().min(MAX_CHUNK);
        let sealed = seal_chunk(&mut this.send, &buf[..take]).map_err(as_io)?;
        this.out.extend_from_slice(&sealed);

        // Кусок собран и принадлежит нам: байты можно считать записанными, а
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
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_shutdown(cx),
            other => other,
        }
    }
}

/// Шифрует один кусок: длину отдельным сообщением, данные — следующим.
///
/// Свободная функция, потому что тем же кадром уходит и первый кусок с
/// заголовком протокола, а собирает его сам протокол — до того, как поток
/// вообще появился.
pub fn seal_chunk(cipher: &mut Cipher, plain: &[u8]) -> TransportResult<Vec<u8>> {
    let length = u16::try_from(plain.len())
        .ok()
        .filter(|_| plain.len() <= MAX_CHUNK)
        .ok_or_else(|| {
            TransportError::malformed(format!("кусок в {} байт длиннее предела", plain.len()))
        })?;

    let mut out = cipher.seal(&length.to_be_bytes())?;
    out.extend_from_slice(&cipher.seal(plain)?);
    Ok(out)
}

/// Ошибка в языке, на котором говорят [`AsyncRead`] и [`AsyncWrite`].
fn as_io(err: TransportError) -> io::Error {
    match err {
        TransportError::Io(err) => err,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;
    use crate::aead::algorithm::Algorithm;

    /// Ключ здесь — это соль, растянутая до нужной длины: проверяется кадр, а
    /// не вывод ключа, и настоящий вывод только мешал бы читать тест.
    fn keying() -> Keying {
        Keying::new(
            Algorithm::Aes128Gcm,
            16,
            Arc::new(|salt: &[u8]| Ok(salt[..16].to_vec())),
        )
    }

    /// Пара «наш поток, сырая сторона собеседника».
    fn pair() -> (ChunkStream<DuplexStream>, DuplexStream) {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let send = keying().cipher(&[1u8; 16]).expect("ключ выводится");
        (ChunkStream::new(ours, keying(), send), theirs)
    }

    /// Собирает то, что прислал бы собеседник: соль и куски за ней.
    fn from_peer(pieces: &[&[u8]]) -> Vec<u8> {
        let salt = [2u8; 16];
        let mut cipher = keying().cipher(&salt).expect("ключ выводится");
        let mut out = salt.to_vec();
        for piece in pieces {
            out.extend_from_slice(&seal_chunk(&mut cipher, piece).expect("шифруется"));
        }
        out
    }

    #[tokio::test]
    async fn what_the_peer_sends_arrives_whole() {
        let (mut stream, mut peer) = pair();
        peer.write_all(&from_peer(&[b"one", b"two"]))
            .await
            .expect("пишется");

        let mut got = [0u8; 6];
        stream.read_exact(&mut got).await.expect("читается");
        assert_eq!(&got, b"onetwo");
    }

    #[tokio::test]
    async fn the_boundary_between_chunks_survives_when_it_is_asked_for() {
        // Ради этого очередь и заведена: у Snell один кусок — это одна
        // датаграмма, и склеить две значит отдать приложению не ту.
        let (mut stream, mut peer) = pair();
        peer.write_all(&from_peer(&[b"first", b"second"]))
            .await
            .expect("пишется");

        assert_eq!(
            stream.read_chunk().await.expect("читается").as_deref(),
            Some(b"first".as_slice())
        );
        assert_eq!(
            stream.read_chunk().await.expect("читается").as_deref(),
            Some(b"second".as_slice())
        );
    }

    #[tokio::test]
    async fn the_byte_view_does_not_lose_a_chunk_it_did_not_finish() {
        // Короткое чтение забирает часть куска; остаток обязан достаться
        // следующему чтению, а не пропасть вместе с границей.
        let (mut stream, mut peer) = pair();
        peer.write_all(&from_peer(&[b"abcdef"]))
            .await
            .expect("пишется");

        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await.expect("читается");
        assert_eq!(&head, b"ab");

        let mut tail = [0u8; 4];
        stream.read_exact(&mut tail).await.expect("читается");
        assert_eq!(&tail, b"cdef");
    }

    #[tokio::test]
    async fn a_reply_arriving_in_pieces_is_assembled() {
        let (mut stream, mut peer) = pair();
        let wire = from_peer(&[b"payload"]);

        let reader = tokio::spawn(async move {
            let mut got = [0u8; 7];
            stream.read_exact(&mut got).await.expect("читается");
            got
        });

        for byte in wire {
            peer.write_all(&[byte]).await.expect("пишется");
            peer.flush().await.expect("уходит");
        }
        assert_eq!(&reader.await.expect("задача"), b"payload");
    }

    #[tokio::test]
    async fn a_wrong_key_looks_like_a_refusal() {
        // Метка не сошлась — значит либо пароль не тот, либо правка по
        // дороге. Различить нельзя, и повторять бессмысленно.
        let (mut stream, mut peer) = pair();
        let mut wire = from_peer(&[b"payload"]);
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        peer.write_all(&wire).await.expect("пишется");

        let mut got = [0u8; 7];
        let err = stream.read_exact(&mut got).await.expect_err("метка не та");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_stream_cut_mid_chunk_is_an_error() {
        // Неполный ответ, отданный как полный, — это тихо испорченные данные.
        let (mut stream, mut peer) = pair();
        let wire = from_peer(&[b"payload"]);
        peer.write_all(&wire[..wire.len() - 3])
            .await
            .expect("пишется");
        drop(peer);

        let mut got = Vec::new();
        let err = stream.read_to_end(&mut got).await.expect_err("обрыв");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn a_peer_that_says_nothing_is_a_clean_end() {
        let (mut stream, peer) = pair();
        drop(peer);

        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.expect("чистый конец");
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn an_absurd_length_is_refused() {
        // Длина больше предела означает, что на том конце не тот протокол.
        let (mut stream, mut peer) = pair();
        let salt = [2u8; 16];
        let mut cipher = keying().cipher(&salt).expect("ключ выводится");
        let mut wire = salt.to_vec();
        wire.extend_from_slice(&cipher.seal(&0xFFFF_u16.to_be_bytes()).expect("шифруется"));
        peer.write_all(&wire).await.expect("пишется");

        let mut got = [0u8; 1];
        let err = stream.read_exact(&mut got).await.expect_err("длина не та");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_long_write_is_cut_into_chunks() {
        let (mut stream, mut peer) = pair();
        stream
            .write_all(&vec![7u8; MAX_CHUNK + 100])
            .await
            .expect("пишется");
        stream.flush().await.expect("уходит");

        // Два куска: полный и остаток. Каждый со своей длиной и меткой.
        let mut wire = vec![0u8; 2 * LENGTH_FRAME + sealed_len(MAX_CHUNK) + sealed_len(100)];
        peer.read_exact(&mut wire).await.expect("читается");
    }

    #[tokio::test]
    async fn a_datagram_goes_out_as_exactly_one_chunk() {
        let (mut stream, mut peer) = pair();
        stream.write_chunk(b"datagram").await.expect("уходит");

        let mut wire = vec![0u8; LENGTH_FRAME + sealed_len(b"datagram".len())];
        peer.read_exact(&mut wire).await.expect("читается");

        // И ничего сверх того: следующий байт придёт только со следующим
        // куском.
        let mut extra = [0u8; 1];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                peer.read_exact(&mut extra)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn a_datagram_too_long_for_a_chunk_is_refused() {
        let (mut stream, _peer) = pair();
        let err = stream
            .write_chunk(&vec![0u8; MAX_CHUNK + 1])
            .await
            .expect_err("не помещается");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
