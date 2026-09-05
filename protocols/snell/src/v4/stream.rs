//! Поток четвёртой версии: свой кадр вместо общего.
//!
//! Отличий от общего кадра три, и все три — про то, как выглядит трафик.
//!
//! **Дополнение.** Первый кадр несёт от 256 до 511 лишних байт, и они лежат
//! **перед** данными, а не после.
//!
//! **Заголовок зашифрован.** У общего кадра открытым текстом идёт длина под
//! своей меткой; здесь под меткой идёт весь заголовок, и длина дополнения в
//! нём же.
//!
//! **Размер кадра растёт.** Первый кадр невелик, дальше предел прибавляется
//! на каждой записи, пока не упрётся в потолок. После полуминуты молчания
//! счёт начинается заново. Так выглядит обычное соединение, которое
//! разгоняется.
//!
//! Ни одно из трёх сервер не проверяет — он читает то, что назвали в
//! заголовке. Значит ошибка здесь стоит не разговора, а сходства с другими
//! клиентами; исключение одно — обмен байтами, без него данные не соберутся.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Buf, BytesMut};
use penguin_transport::aead::{Cipher, Keying, TAG_LEN};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::v4::frame::{
    self, FRAME_SIZE, HEADER_LEN, INITIAL_PADDING_MIN, INITIAL_PADDING_SPAN, MAX_PAYLOAD, SALT_LEN,
};

/// Сколько байт занимает заголовок вместе с меткой.
const HEADER_SEALED: usize = HEADER_LEN + TAG_LEN;

/// После какого молчания предел размера кадра сбрасывается.
const IDLE: Duration = Duration::from_secs(30);

/// Сколько байт брать из сокета за раз.
const READ_CHUNK: usize = 16 * 1024;

/// Сколько зашифрованного копить, прежде чем перестать принимать новое.
const OUT_LIMIT: usize = 256 * 1024;

/// Что читатель ждёт сейчас.
#[derive(Debug, Clone, Copy)]
enum Await {
    /// Соль собеседника.
    Salt,
    /// Заголовок вместе с меткой.
    Header,
    /// Дополнение и данные.
    Body {
        /// Сколько байт дополнения перед данными.
        padding: usize,
        /// Сколько байт данных.
        payload: usize,
    },
}

/// Поток четвёртой версии.
pub struct V4Stream<S> {
    io: S,
    keying: Keying,
    /// Шифр на отправку. Готов сразу: соль мы бросили сами.
    send: Cipher,
    /// Наша соль. Уходит вместе с первым кадром.
    salt: Vec<u8>,
    /// Соль уже ушла.
    salt_sent: bool,
    /// Шифр на приём. `None`, пока собеседник не прислал свою соль.
    recv: Option<Cipher>,
    /// Что читается сейчас.
    step: Await,
    /// Собеседник объявил конец: кадр без данных.
    finished: bool,

    /// Сырое из сокета, ещё не разобранное.
    incoming: BytesMut,
    /// Расшифрованные кадры, ещё не отданные читателю.
    ready: VecDeque<BytesMut>,
    /// Зашифрованное, ещё не ушедшее в сокет.
    out: BytesMut,

    /// Дополнение первого кадра.
    initial_padding: u16,
    /// Предел данных в кадре: растёт с каждой записью.
    payload_limit: u16,
    /// Когда писали в прошлый раз.
    last_write: Option<Instant>,
}

impl<S> std::fmt::Debug for V4Stream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V4Stream")
            .field("ready", &self.ready.len())
            .field("out", &self.out.len())
            .finish()
    }
}

impl<S> V4Stream<S> {
    /// Заводит поток. Соль при этом не уходит — она уедет с первым кадром.
    pub fn new(io: S, keying: Keying, salt: Vec<u8>, send: Cipher) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            io,
            keying,
            send,
            salt,
            salt_sent: false,
            recv: None,
            step: Await::Salt,
            finished: false,
            incoming: BytesMut::new(),
            ready: VecDeque::new(),
            out: BytesMut::new(),
            initial_padding: INITIAL_PADDING_MIN + rng.gen_range(0..INITIAL_PADDING_SPAN),
            payload_limit: 0,
            last_write: None,
        }
    }

    /// Сколько данных положить в следующий кадр.
    ///
    /// Первый кадр невелик — из него ещё вычитается дополнение, — дальше
    /// предел прибавляется на каждой записи. После [`IDLE`] молчания счёт
    /// начинается заново: так выглядит соединение, которое отдохнуло.
    fn next_payload_limit(&mut self) -> usize {
        let now = Instant::now();
        let limit = match self.last_write {
            None => (FRAME_SIZE as u16)
                .saturating_sub(55)
                .saturating_sub(self.initial_padding),
            Some(last) if now.duration_since(last) > IDLE => (FRAME_SIZE as u16).saturating_sub(39),
            Some(_) => self.payload_limit,
        };
        self.last_write = Some(now);

        self.payload_limit = if usize::from(limit) < MAX_PAYLOAD {
            (usize::from(limit) + FRAME_SIZE - 39).min(MAX_PAYLOAD) as u16
        } else {
            MAX_PAYLOAD as u16
        };

        let limit = usize::from(limit);
        if limit == 0 || limit > MAX_PAYLOAD {
            MAX_PAYLOAD
        } else {
            limit
        }
    }

    /// Сколько дополнения положить в кадр.
    ///
    /// Только в первый и только если в нём есть данные: дальше дополнение не
    /// нужно, разгон размеров делает ту же работу дешевле.
    fn next_padding(&self, payload: usize) -> usize {
        if self.salt_sent || payload == 0 {
            return 0;
        }
        usize::from(self.initial_padding)
    }

    /// Собирает кадр и кладёт его в очередь на отправку.
    fn queue_frame(&mut self, payload: &[u8], padding_len: usize) -> io::Result<()> {
        if payload.len() > MAX_PAYLOAD || padding_len > MAX_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "кадр Snell v4 длиннее предела",
            ));
        }
        if payload.is_empty() && padding_len != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "кадр Snell v4 без данных, но с дополнением",
            ));
        }

        let header = frame::header(padding_len, payload.len());
        let sealed_header = self.send.seal(&header).map_err(as_io)?;

        let mut sealed_payload = if payload.is_empty() {
            Vec::new()
        } else {
            self.send.seal(payload).map_err(as_io)?
        };

        if !self.salt_sent {
            self.out.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }
        self.out.extend_from_slice(&sealed_header);

        if padding_len > 0 {
            let mut padding = frame::padding(&sealed_payload, padding_len);
            frame::swap(&mut padding, &mut sealed_payload);
            self.out.extend_from_slice(&padding);
        }
        self.out.extend_from_slice(&sealed_payload);
        Ok(())
    }
}

impl<S: AsyncWrite + Unpin> V4Stream<S> {
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

    /// Отправляет один кадр и доводит его до сокета.
    pub async fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        let padding = self.next_padding(payload.len());
        self.queue_frame(payload, padding)?;

        std::future::poll_fn(|cx| self.poll_drain(cx)).await?;
        std::future::poll_fn(|cx| Pin::new(&mut self.io).poll_flush(cx)).await
    }
}

impl<S: AsyncRead + Unpin> V4Stream<S> {
    /// Двигает разбор на шаг. `Ok(false)` — байт пока не хватает.
    fn take_step(&mut self) -> io::Result<bool> {
        match self.step {
            Await::Salt => {
                if self.incoming.len() < SALT_LEN {
                    return Ok(false);
                }
                let salt = self.incoming.split_to(SALT_LEN);
                self.recv = Some(self.keying.cipher(&salt).map_err(as_io)?);
                self.step = Await::Header;
                Ok(true)
            }
            Await::Header => {
                if self.incoming.len() < HEADER_SEALED {
                    return Ok(false);
                }
                let Some(recv) = self.recv.as_mut() else {
                    return Ok(false);
                };

                let mut sealed = self.incoming.split_to(HEADER_SEALED);
                let plain = recv.open(&mut sealed).map_err(as_io)?;
                let Some(header) = frame::parse(&sealed[..plain]) else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "заголовок не от четвёртой версии Snell",
                    ));
                };

                // Кадр без данных — это объявленный конец: так собеседник
                // говорит «больше не пишу». С дополнением такого не бывает.
                if header.payload == 0 {
                    if header.padding != 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "кадр Snell v4 без данных, но с дополнением",
                        ));
                    }
                    self.finished = true;
                    return Ok(false);
                }

                self.step = Await::Body {
                    padding: header.padding,
                    payload: header.payload,
                };
                Ok(true)
            }
            Await::Body { padding, payload } => {
                let want = padding + payload + TAG_LEN;
                if self.incoming.len() < want {
                    return Ok(false);
                }
                let Some(recv) = self.recv.as_mut() else {
                    return Ok(false);
                };

                let mut body = self.incoming.split_to(want);
                if padding > 0 {
                    let (left, right) = body.split_at_mut(padding);
                    frame::swap(left, right);
                }

                let mut sealed = body.split_off(padding);
                let plain = recv.open(&mut sealed).map_err(as_io)?;
                sealed.truncate(plain);
                self.ready.push_back(sealed);

                self.step = Await::Header;
                Ok(true)
            }
        }
    }

    /// Двигает разбор, пока не появится кадр или не кончится поток.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            if !self.ready.is_empty() {
                return Poll::Ready(Ok(true));
            }
            if self.finished {
                return Poll::Ready(Ok(false));
            }

            match self.take_step() {
                Ok(true) => continue,
                Ok(false) if self.finished => return Poll::Ready(Ok(false)),
                Ok(false) => {}
                Err(err) => return Poll::Ready(Err(err)),
            }

            let before = self.incoming.len();
            self.incoming.resize(before + READ_CHUNK, 0);
            let mut chunk = ReadBuf::new(&mut self.incoming[before..]);

            let result = Pin::new(&mut self.io).poll_read(cx, &mut chunk);
            let filled = chunk.filled().len();
            self.incoming.truncate(before + filled);

            match result {
                Poll::Ready(Ok(())) if filled == 0 => {
                    // Оборванный кадр — потерянные данные, и отдать их как
                    // обычный конец значит показать неполный ответ полным.
                    return Poll::Ready(if self.mid_frame() {
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

    /// Ждём ли мы сейчас продолжения того, что уже начали читать.
    fn mid_frame(&self) -> bool {
        !self.incoming.is_empty() || matches!(self.step, Await::Body { .. })
    }

    /// Читает один кадр целиком. `Ok(None)` — поток кончился.
    pub async fn read_frame(&mut self) -> io::Result<Option<BytesMut>> {
        std::future::poll_fn(|cx| match self.poll_ready(cx) {
            Poll::Ready(Ok(true)) => Poll::Ready(Ok(self.ready.pop_front())),
            Poll::Ready(Ok(false)) => Poll::Ready(Ok(None)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        })
        .await
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for V4Stream<S> {
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

impl<S: AsyncWrite + Unpin> AsyncWrite for V4Stream<S> {
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

        let take = buf.len().min(this.next_payload_limit());
        let padding = this.next_padding(take);
        if let Err(err) = this.queue_frame(&buf[..take], padding) {
            return Poll::Ready(Err(err));
        }

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
fn as_io(err: penguin_transport::TransportError) -> io::Error {
    match err {
        penguin_transport::TransportError::Io(err) => err,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

#[cfg(test)]
mod tests {
    use penguin_transport::aead::Algorithm;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;
    use crate::crypto;

    const PSK: &str = "общий ключ";

    fn keying() -> Keying {
        crypto::keying(PSK.to_owned(), Algorithm::Aes128Gcm)
    }

    /// Пара «наш поток, поток собеседника».
    fn pair() -> (V4Stream<DuplexStream>, V4Stream<DuplexStream>) {
        let (ours, theirs) = tokio::io::duplex(1024 * 1024);
        (side(ours, 1), side(theirs, 2))
    }

    /// Одна сторона со своей солью.
    fn side(io: DuplexStream, mark: u8) -> V4Stream<DuplexStream> {
        let salt = vec![mark; SALT_LEN];
        let send = keying().cipher(&salt).expect("ключ выводится");
        V4Stream::new(io, keying(), salt, send)
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
    async fn the_first_frame_carries_padding_and_the_next_one_does_not() {
        // Дополнение только в первом кадре: дальше ту же работу делает разгон
        // размеров, и он дешевле.
        let (ours, mut raw) = tokio::io::duplex(1024 * 1024);
        let mut client = side(ours, 1);

        client.write_all(b"one").await.expect("пишется");
        client.flush().await.expect("уходит");

        let want = SALT_LEN + HEADER_SEALED + usize::from(client.initial_padding) + 3 + TAG_LEN;
        let mut first = vec![0u8; want];
        raw.read_exact(&mut first).await.expect("читается");
        assert_eq!(&first[..SALT_LEN], &[1u8; SALT_LEN], "соль ушла не первой");

        client.write_all(b"two").await.expect("пишется");
        client.flush().await.expect("уходит");

        // Второй кадр — только заголовок и данные, без соли и дополнения.
        let mut second = vec![0u8; HEADER_SEALED + 3 + TAG_LEN];
        raw.read_exact(&mut second).await.expect("читается");
    }

    #[tokio::test]
    async fn the_boundary_of_a_frame_survives_when_it_is_asked_for() {
        // У датаграмм граница кадра — это граница посылки.
        let (mut client, mut server) = pair();
        client.write_frame(b"first").await.expect("уходит");
        client.write_frame(b"second").await.expect("уходит");

        assert_eq!(
            server.read_frame().await.expect("читается").as_deref(),
            Some(b"first".as_slice())
        );
        assert_eq!(
            server.read_frame().await.expect("читается").as_deref(),
            Some(b"second".as_slice())
        );
    }

    #[tokio::test]
    async fn a_long_write_is_cut_into_frames() {
        let (mut client, mut server) = pair();
        let payload = vec![7u8; 40 * 1024];

        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.expect("пишется");
            client.flush().await.expect("уходит");
        });

        let mut got = vec![0u8; 40 * 1024];
        server.read_exact(&mut got).await.expect("читается");
        assert!(got.iter().all(|byte| *byte == 7));
        writer.await.expect("задача");
    }

    #[tokio::test]
    async fn a_reply_arriving_in_pieces_is_assembled() {
        let (mut client, mut server) = pair();
        client.write_all(b"payload").await.expect("пишется");
        client.flush().await.expect("уходит");

        // Читаем по байту: разбор обязан склеить кадр из кусков.
        let mut got = Vec::new();
        while got.len() < 7 {
            let mut byte = [0u8; 1];
            server.read_exact(&mut byte).await.expect("читается");
            got.push(byte[0]);
        }
        assert_eq!(got, b"payload");
    }

    #[tokio::test]
    async fn a_frame_without_data_is_the_end_of_the_stream() {
        // Так собеседник говорит «больше не пишу».
        let (mut client, mut server) = pair();
        client.write_frame(b"tail").await.expect("уходит");
        client.write_frame(&[]).await.expect("уходит");

        let mut got = Vec::new();
        server.read_to_end(&mut got).await.expect("чистый конец");
        assert_eq!(got, b"tail");
    }

    #[tokio::test]
    async fn a_wrong_key_looks_like_a_refusal() {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let mut client = side(ours, 1);

        let other = crypto::keying("не тот ключ".to_owned(), Algorithm::Aes128Gcm);
        let salt = vec![2u8; SALT_LEN];
        let send = other.cipher(&salt).expect("ключ выводится");
        let mut server = V4Stream::new(theirs, other, salt, send);

        client.write_all(b"payload").await.expect("пишется");
        client.flush().await.expect("уходит");

        let mut got = [0u8; 7];
        let err = server.read_exact(&mut got).await.expect_err("метка не та");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_stream_cut_mid_frame_is_an_error() {
        // Неполный кадр, отданный как конец потока, — это тихо испорченные
        // данные.
        let (ours, mut raw) = tokio::io::duplex(1024 * 1024);
        let mut client = side(ours, 1);
        client.write_frame(b"payload").await.expect("уходит");

        let want = SALT_LEN + HEADER_SEALED + usize::from(client.initial_padding) + 7 + TAG_LEN;
        let mut wire = vec![0u8; want];
        raw.read_exact(&mut wire).await.expect("читается");

        let (theirs, mut feed) = tokio::io::duplex(1024 * 1024);
        let mut server = side(theirs, 2);
        feed.write_all(&wire[..wire.len() - 3])
            .await
            .expect("пишется");
        drop(feed);

        let mut got = Vec::new();
        let err = server.read_to_end(&mut got).await.expect_err("обрыв");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn the_frame_limit_grows_and_starts_over_after_a_pause() {
        let (io, _) = tokio::io::duplex(16);
        let mut stream = side(io, 1);

        let first = stream.next_payload_limit();
        let second = stream.next_payload_limit();
        assert!(second > first, "предел не растёт: {first} и {second}");

        // Он не растёт бесконечно: потолок — предел кадра.
        for _ in 0..64 {
            stream.next_payload_limit();
        }
        assert_eq!(stream.next_payload_limit(), MAX_PAYLOAD);
    }

    #[test]
    fn the_first_frame_is_smaller_by_exactly_its_padding() {
        // Дополнение вычитается из предела: кадр целиком обязан уложиться в
        // тот же размер, что и обычный.
        let (io, _) = tokio::io::duplex(16);
        let mut stream = side(io, 1);

        let padding = usize::from(stream.initial_padding);
        assert_eq!(stream.next_payload_limit(), FRAME_SIZE - 55 - padding);
    }
}
