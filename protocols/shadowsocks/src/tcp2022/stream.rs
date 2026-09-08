//! Поток TCP 2022 поверх обычного соединения.
//!
//! ```text
//!  ──► [соль] [AEAD(тип+время+длина)] [AEAD(адрес+дополнение)] [длина+метка] [кусок+метка] ...
//!       ^^^^^^                        ^^^^^^^^^^^^^^^^^^^^^^^^
//!       открытым текстом,             это и есть первый «кусок данных» —
//!       один раз в начале             отдельного поля длины перед ним нет
//! ```
//!
//! Отдельный тип, а не [`penguin_transport::aead::ChunkStream`]: у 2022 два
//! настоящих различия с обычным AEAD, а не одно. Вывод подключа — уже дело
//! [`crate::kdf2022`], это `ChunkStream` и так принимает через `Keying`. Но
//! кадр здесь **начинается иначе** — двумя кусками фиксированного и
//! переменного заголовка вместо одной пары «длина, данные», — и потолок
//! куска другой: 0xFFFF, а не 0x3FFF, потому что 2022 не отдаёт под служебные
//! биты старшие два бита длины (сверено в `shadowsocks-rust`:
//! `relay/tcprelay/aead_2022.rs::MAX_PACKET_SIZE`).
//!
//! Заголовок запроса отправляет [`crate::outbound`] — до того, как этот тип
//! вообще появляется, точно как это устроено у обычного AEAD
//! ([`crate::stream`]). Здесь начинается уже установившийся обмен: шифр
//! отправки передаётся с уже сдвинутым на два шага счётчиком, а шифр приёма
//! появляется по мере того, как приходит соль и заголовок ответа.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use penguin_transport::aead::{Algorithm, Cipher, TAG_LEN, sealed_len};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{ShadowsocksError, ShadowsocksResult};
use crate::header2022;
use crate::kdf2022;
use crate::tcp2022::header;

/// Наибольший кусок данных: у 2022 под него отдана вся длина, обе служебные
/// биты 2022 не резервирует (в отличие от обычного AEAD).
pub const MAX_CHUNK: usize = 0xFFFF;

/// Сколько байт занимает зашифрованная длина куска: два байта и метка.
const LENGTH_FRAME: usize = 2 + TAG_LEN;

/// Сколько байт брать из сокета за раз.
const READ_CHUNK: usize = 16 * 1024;

/// Сколько зашифрованного можно накопить, прежде чем перестать принимать
/// новое.
const OUT_LIMIT: usize = 256 * 1024;

/// Что ещё нужно, прежде чем поток сможет отдавать обычные данные.
enum RecvState {
    /// Ждём соль собеседника: без неё не из чего вывести подключ.
    AwaitingSalt,
    /// Соль пришла, подключ выведен; ждём фиксированную часть заголовка
    /// ответа (тип, метка времени, эхо нашей соли, длина первого куска).
    AwaitingFixedHeader(Cipher),
    /// Рукопожатие пройдено; шифр обычных кусков данных.
    Established(Cipher),
}

/// Поток Shadowsocks 2022 поверх уже подключённого соединения.
pub struct Ss2022Stream<S> {
    io: S,
    algorithm: Algorithm,
    psk: Vec<u8>,
    salt_len: usize,
    /// Соль, которую отправили мы, — сервер обязан подтвердить её же.
    request_salt: Vec<u8>,
    send: Cipher,
    recv: RecvState,
    /// Длина следующего куска данных, если она уже известна.
    expect: Option<usize>,
    out: BytesMut,
    incoming: BytesMut,
    ready: VecDeque<BytesMut>,
}

impl<S> std::fmt::Debug for Ss2022Stream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ss2022Stream")
            .field("algorithm", &self.algorithm.name())
            .field("ready", &self.ready.len())
            .finish()
    }
}

impl<S> Ss2022Stream<S> {
    /// Оборачивает соединение, в которое уже отправлены соль и заголовок
    /// запроса. `send` — шифр, которым этот заголовок уже зашифрован: его
    /// счётчик должен быть сдвинут ровно на два шага (фиксированная часть,
    /// переменная часть), не на ноль.
    pub fn new(
        io: S,
        algorithm: Algorithm,
        psk: Vec<u8>,
        salt_len: usize,
        request_salt: Vec<u8>,
        send: Cipher,
    ) -> Self {
        Self {
            io,
            algorithm,
            psk,
            salt_len,
            request_salt,
            send,
            recv: RecvState::AwaitingSalt,
            expect: None,
            out: BytesMut::new(),
            incoming: BytesMut::new(),
            ready: VecDeque::new(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Ss2022Stream<S> {
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

    /// Продвигает разбор на один шаг. `Ok(false)` — байт пока не хватает.
    fn take_step(&mut self) -> ShadowsocksResult<bool> {
        match &self.recv {
            RecvState::AwaitingSalt => {
                if self.incoming.len() < self.salt_len {
                    return Ok(false);
                }
                let salt = self.incoming.split_to(self.salt_len);
                let key = kdf2022::derive(&self.psk, &salt, self.algorithm.key_len());
                let cipher = Cipher::new(self.algorithm, &key)?;
                self.recv = RecvState::AwaitingFixedHeader(cipher);
                Ok(true)
            }
            RecvState::AwaitingFixedHeader(_) => {
                let fixed_len = header::response_fixed_len(self.salt_len);
                let sealed = sealed_len(fixed_len);
                if self.incoming.len() < sealed {
                    return Ok(false);
                }
                let RecvState::AwaitingFixedHeader(mut cipher) =
                    std::mem::replace(&mut self.recv, RecvState::AwaitingSalt)
                else {
                    unreachable!("состояние проверено веткой выше");
                };

                let mut frame = self.incoming.split_to(sealed);
                let plain = cipher.open(&mut frame)?;
                let length = header::decode_response_fixed(
                    &frame[..plain],
                    &self.request_salt,
                    header2022::now_unix(),
                )?;

                self.expect = Some(usize::from(length));
                self.recv = RecvState::Established(cipher);
                Ok(true)
            }
            RecvState::Established(_) => {
                let RecvState::Established(cipher) = &mut self.recv else {
                    unreachable!("состояние проверено веткой выше");
                };

                match self.expect {
                    None => {
                        if self.incoming.len() < LENGTH_FRAME {
                            return Ok(false);
                        }
                        let mut frame = self.incoming.split_to(LENGTH_FRAME);
                        let plain = cipher.open(&mut frame)?;
                        let Some(raw) = frame.get(..plain).and_then(<[u8]>::first_chunk::<2>)
                        else {
                            return Err(ShadowsocksError::malformed(
                                "длина куска 2022 не на месте",
                            ));
                        };
                        self.expect = Some(usize::from(u16::from_be_bytes(*raw)));
                        Ok(true)
                    }
                    Some(length) => {
                        if self.incoming.len() < sealed_len(length) {
                            return Ok(false);
                        }
                        let mut frame = self.incoming.split_to(sealed_len(length));
                        let plain = cipher.open(&mut frame)?;
                        frame.truncate(plain);
                        self.ready.push_back(frame);
                        self.expect = None;
                        Ok(true)
                    }
                }
            }
        }
    }

    fn mid_message(&self) -> bool {
        !matches!(self.recv, RecvState::AwaitingSalt) || !self.incoming.is_empty()
    }

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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Ss2022Stream<S> {
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Ss2022Stream<S> {
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

        let take = buf.len().min(MAX_CHUNK);
        let sealed = seal_chunk(&mut this.send, &buf[..take]).map_err(as_io)?;
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

/// Шифрует один кусок обычных данных: длину отдельным сообщением, данные —
/// следующим. Не [`penguin_transport::aead::seal_chunk`]: у него предел
/// 0x3FFF, у 2022 — 0xFFFF (см. документ модуля).
fn seal_chunk(cipher: &mut Cipher, plain: &[u8]) -> ShadowsocksResult<Vec<u8>> {
    let length = u16::try_from(plain.len()).map_err(|_| {
        ShadowsocksError::malformed(format!("кусок 2022 в {} байт длиннее предела", plain.len()))
    })?;

    let mut out = cipher.seal(&length.to_be_bytes())?;
    out.extend_from_slice(&cipher.seal(plain)?);
    Ok(out)
}

/// Ошибка в языке, на котором говорят [`AsyncRead`] и [`AsyncWrite`].
fn as_io(err: ShadowsocksError) -> io::Error {
    match err {
        ShadowsocksError::Io(err) => err,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;
    use crate::kdf2022;

    const ALGORITHM: Algorithm = Algorithm::Aes128Gcm;
    const SALT_LEN: usize = 16;
    const PSK: [u8; 16] = [9u8; 16];

    /// Собирает пару «наш поток, сырая сторона сервера» с уже отправленным
    /// (в тесте — руками, а не через `outbound`) заголовком запроса.
    fn pair() -> (
        Ss2022Stream<tokio::io::DuplexStream>,
        tokio::io::DuplexStream,
    ) {
        let (client, server) = duplex(64 * 1024);

        let request_salt = vec![1u8; SALT_LEN];
        let key = kdf2022::derive(&PSK, &request_salt, ALGORITHM.key_len());
        let mut send = Cipher::new(ALGORITHM, &key).expect("ключ подходит");

        // Тот же порядок, что и `outbound`: сначала фиксированная часть,
        // потом переменная — оба шага двигают счётчик отправки.
        let _ = send.seal(b"01234567890").expect("шифруется"); // 11 байт-заглушка фиксированной части
        let _ = send.seal(b"variable-part").expect("шифруется");

        let stream = Ss2022Stream::new(
            client,
            ALGORITHM,
            PSK.to_vec(),
            SALT_LEN,
            request_salt,
            send,
        );
        (stream, server)
    }

    /// Собирает то, что прислал бы сервер: свою соль, заголовок ответа,
    /// куски данных.
    fn from_server(request_salt: &[u8], pieces: &[&[u8]]) -> Vec<u8> {
        let server_salt = vec![2u8; SALT_LEN];
        let key = kdf2022::derive(&PSK, &server_salt, ALGORITHM.key_len());
        let mut cipher = Cipher::new(ALGORITHM, &key).expect("ключ подходит");

        let first = pieces.first().copied().unwrap_or(b"".as_slice());

        let mut plain = vec![header2022::TYPE_SERVER];
        plain.extend_from_slice(&header2022::now_unix().to_be_bytes());
        plain.extend_from_slice(request_salt);
        plain.extend_from_slice(&(first.len() as u16).to_be_bytes());

        let mut out = server_salt;
        out.extend_from_slice(&cipher.seal(&plain).expect("шифруется"));
        out.extend_from_slice(&cipher.seal(first).expect("шифруется"));

        for piece in pieces.iter().skip(1) {
            out.extend_from_slice(&seal_chunk(&mut cipher, piece).expect("шифруется"));
        }
        out
    }

    #[tokio::test]
    async fn what_the_server_sends_arrives_whole() {
        let (mut stream, mut server) = pair();
        server
            .write_all(&from_server(&[1u8; SALT_LEN], &[b"first ", b"second"]))
            .await
            .expect("ушло");

        let mut got = [0u8; 12];
        stream.read_exact(&mut got).await.expect("пришло");
        assert_eq!(&got, b"first second");
    }

    #[tokio::test]
    async fn a_response_to_someone_elses_request_is_rejected() {
        let (mut stream, mut server) = pair();
        server
            .write_all(&from_server(&[9u8; SALT_LEN], &[b"payload"]))
            .await
            .expect("ушло");

        let mut got = [0u8; 7];
        let err = stream.read_exact(&mut got).await.expect_err("соль не та");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_write_longer_than_the_2022_cap_is_split_but_not_at_the_legacy_cap() {
        // 0x3FFF (предел обычного AEAD) не должен резать кусок здесь: у
        // 2022 предел — 0xFFFF.
        let (mut stream, mut server) = pair();
        let payload = vec![7u8; 0x3FFF + 1000];

        let writer = tokio::spawn(async move {
            stream.write_all(&payload).await.expect("ушло");
            stream.flush().await.expect("сброшено");
        });

        let mut head = vec![0u8; LENGTH_FRAME];
        server.read_exact(&mut head).await.expect("пришло");
        let mut body = vec![0u8; sealed_len(0x3FFF + 1000)];
        server
            .read_exact(&mut body)
            .await
            .expect("весь кусок одним куском");

        writer.await.expect("задача");
    }

    #[tokio::test]
    async fn a_server_that_says_nothing_before_the_salt_is_a_clean_end() {
        let (mut stream, server) = pair();
        drop(server);

        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.expect("чистый конец");
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn a_stream_cut_mid_header_is_an_error_not_a_clean_end() {
        let (mut stream, mut server) = pair();
        let wire = from_server(&[1u8; SALT_LEN], &[b"payload"]);
        server.write_all(&wire[..SALT_LEN + 3]).await.expect("ушло");
        drop(server);

        let mut got = Vec::new();
        let err = stream.read_to_end(&mut got).await.expect_err("оборвано");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
