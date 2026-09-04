//! Поток, зашифрованный целиком.
//!
//! ```text
//!  ──► [соль] [длина+метка] [кусок+метка] [длина+метка] [кусок+метка] ...
//!       ^^^^^^
//!       открытым текстом, один раз в начале
//! ```
//!
//! Заголовков у Shadowsocks нет вовсе: с первого байта после соли идёт шифр.
//! Адрес назначения — тоже внутри, первым куском, и снаружи его не видно.
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
//! поле `expect` у [`SsStream`] до тех пор, пока не придёт весь кусок.
//!
//! # Предел куска
//!
//! Длина пишется двумя байтами, но старшие два бита протокол оставляет себе:
//! кусок не бывает длиннее [`MAX_CHUNK`]. Сервер, объявивший больше, — это не
//! сервер Shadowsocks, и продолжать после такого нечего.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::crypto::cipher::sealed_len;
use crate::crypto::method::TAG_LEN;
use crate::crypto::{Cipher, Method, kdf};
use crate::error::ShadowsocksError;

/// Наибольший кусок, какой позволяет протокол.
pub const MAX_CHUNK: usize = 0x3FFF;

/// Сколько байт занимает зашифрованная длина: два байта и метка.
const LENGTH_FRAME: usize = 2 + TAG_LEN;

/// Сколько байт брать из сокета за раз.
const READ_CHUNK: usize = 16 * 1024;

/// Сколько зашифрованного можно накопить, прежде чем перестать принимать новое.
const OUT_LIMIT: usize = 256 * 1024;

/// Поток Shadowsocks поверх обычного соединения.
pub struct SsStream<S> {
    io: S,
    method: Method,
    /// Главный ключ: из него и присланной соли выводится ключ на приём.
    master: Vec<u8>,
    /// Шифр на отправку. Готов сразу: соль мы бросили сами.
    send: Cipher,
    /// Шифр на приём. `None`, пока сервер не прислал свою соль.
    recv: Option<Cipher>,
    /// Длина куска, уже расшифрованная и ещё не использованная.
    expect: Option<usize>,
    /// Зашифрованное, ещё не ушедшее в сокет.
    out: BytesMut,
    /// Сырое из сокета, ещё не разобранное.
    incoming: BytesMut,
    /// Расшифрованное, ещё не отданное читателю.
    ready: BytesMut,
}

impl<S> std::fmt::Debug for SsStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsStream")
            .field("method", &self.method.name())
            .field("ready", &self.ready.len())
            .field("out", &self.out.len())
            .finish()
    }
}

impl<S> SsStream<S> {
    /// Оборачивает соединение, в которое уже отправлены соль и адрес.
    pub fn new(io: S, method: Method, master: Vec<u8>, send: Cipher) -> Self {
        Self {
            io,
            method,
            master,
            send,
            recv: None,
            expect: None,
            out: BytesMut::new(),
            incoming: BytesMut::new(),
            ready: BytesMut::new(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> SsStream<S> {
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
    fn take_step(&mut self) -> Result<bool, ShadowsocksError> {
        if self.recv.is_none() {
            let salt_len = self.method.salt_len();
            if self.incoming.len() < salt_len {
                return Ok(false);
            }
            let salt = self.incoming.split_to(salt_len);
            let key = kdf::session_key(&self.master, &salt, self.method)?;
            self.recv = Some(Cipher::new(self.method, &key)?);
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
                    return Err(ShadowsocksError::malformed("длина куска не на месте"));
                };

                let length = usize::from(u16::from_be_bytes(*raw));
                // Ноль означал бы кусок без данных, то есть шаг счётчика
                // впустую; больше предела — что на том конце не Shadowsocks.
                if length == 0 || length > MAX_CHUNK {
                    return Err(ShadowsocksError::malformed(format!(
                        "кусок в {length} байт: протокол такого не допускает"
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
                self.ready.extend_from_slice(&frame[..plain]);
                self.expect = None;
                Ok(true)
            }
        }
    }

    /// Ждём ли мы сейчас продолжения того, что уже начали читать.
    fn mid_message(&self) -> bool {
        self.expect.is_some() || !self.incoming.is_empty()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for SsStream<S> {
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
                    // Оборванный на середине кусок — это потерянные данные, и
                    // отдать их наверх как обычный конец потока значит
                    // показать приложению неполный ответ как полный.
                    return Poll::Ready(if this.mid_message() {
                        Err(io::Error::from(io::ErrorKind::UnexpectedEof))
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SsStream<S> {
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
/// адресом назначения, а собирает его [`crate::outbound`].
pub fn seal_chunk(cipher: &mut Cipher, plain: &[u8]) -> Result<Vec<u8>, ShadowsocksError> {
    let length = u16::try_from(plain.len())
        .ok()
        .filter(|_| plain.len() <= MAX_CHUNK)
        .ok_or_else(|| {
            ShadowsocksError::crypto(format!("кусок в {} байт длиннее предела", plain.len()))
        })?;

    let mut out = cipher.seal(&length.to_be_bytes())?;
    out.extend_from_slice(&cipher.seal(plain)?);
    Ok(out)
}

/// Ошибка протокола в языке, на котором говорят [`AsyncRead`] и [`AsyncWrite`].
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

    const METHOD: Method = Method::Aes256Gcm;
    const PASSWORD: &str = "пароль от сервера";

    /// Собирает пару «клиент, сервер» с общим паролем.
    ///
    /// Сервер здесь ненастоящий: он умеет только то же, что клиент, — и это
    /// ровно то, что нужно, чтобы проверить кадры без сети.
    fn pair() -> (
        SsStream<tokio::io::DuplexStream>,
        tokio::io::DuplexStream,
        Vec<u8>,
    ) {
        let (client, server) = duplex(1024 * 1024);
        let master = kdf::master_key(PASSWORD, METHOD);

        let salt = vec![3u8; METHOD.salt_len()];
        let key = kdf::session_key(&master, &salt, METHOD).expect("выводится");
        let send = Cipher::new(METHOD, &key).expect("ключ подходит");

        (
            SsStream::new(client, METHOD, master.clone(), send),
            server,
            master,
        )
    }

    /// Собирает то, что прислал бы сервер: свою соль и куски под ней.
    fn from_server(master: &[u8], pieces: &[&[u8]]) -> Vec<u8> {
        let salt = vec![9u8; METHOD.salt_len()];
        let key = kdf::session_key(master, &salt, METHOD).expect("выводится");
        let mut cipher = Cipher::new(METHOD, &key).expect("ключ подходит");

        let mut out = salt;
        for piece in pieces {
            out.extend_from_slice(&seal_chunk(&mut cipher, piece).expect("шифруется"));
        }
        out
    }

    #[tokio::test]
    async fn what_the_server_sends_arrives_whole() {
        let (mut client, mut server, master) = pair();
        server
            .write_all(&from_server(&master, &[b"first ", b"second"]))
            .await
            .expect("ушло");

        let mut got = [0u8; 12];
        client.read_exact(&mut got).await.expect("пришло");
        assert_eq!(&got, b"first second");
    }

    #[tokio::test]
    async fn a_reply_arriving_in_pieces_is_assembled() {
        // Соль, длина и кусок приезжают тремя пакетами — обычное дело.
        let (mut client, mut server, master) = pair();
        let wire = from_server(&master, &[b"payload"]);

        let reader = tokio::spawn(async move {
            let mut got = [0u8; 7];
            client.read_exact(&mut got).await.expect("пришло");
            got
        });

        for byte in wire {
            server.write_all(&[byte]).await.expect("ушло");
        }
        assert_eq!(&reader.await.expect("задача"), b"payload");
    }

    #[tokio::test]
    async fn a_wrong_password_looks_like_a_refusal() {
        // Отказа у Shadowsocks нет: сервер с другим паролем просто пришлёт то,
        // что у нас не расшифруется. Это и есть «неверный пароль».
        let (mut client, mut server, _) = pair();
        let other = kdf::master_key("другой пароль", METHOD);
        server
            .write_all(&from_server(&other, &[b"payload"]))
            .await
            .expect("ушло");

        let mut got = [0u8; 7];
        let err = client.read_exact(&mut got).await.expect_err("не сошлось");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("метка подлинности"), "{err}");
    }

    #[tokio::test]
    async fn a_changed_byte_is_noticed() {
        let (mut client, mut server, master) = pair();
        let mut wire = from_server(&master, &[b"payload"]);
        let last = wire.len() - 1;
        wire[last] ^= 1;
        server.write_all(&wire).await.expect("ушло");

        let mut got = [0u8; 7];
        assert!(client.read_exact(&mut got).await.is_err());
    }

    #[tokio::test]
    async fn a_stream_cut_mid_chunk_is_an_error() {
        let (mut client, mut server, master) = pair();
        let wire = from_server(&master, &[b"payload"]);
        server
            .write_all(&wire[..wire.len() - 3])
            .await
            .expect("ушло");
        drop(server);

        let mut got = Vec::new();
        let err = client.read_to_end(&mut got).await.expect_err("оборвано");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn a_server_that_says_nothing_is_a_clean_end() {
        // Сервер вправе закрыть соединение, не прислав даже соли.
        let (mut client, server, _) = pair();
        drop(server);

        let mut got = Vec::new();
        client.read_to_end(&mut got).await.expect("чистый конец");
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn an_absurd_length_is_refused() {
        // Больше предела протокол не допускает: на том конце не Shadowsocks.
        let (mut client, mut server, master) = pair();

        let salt = vec![9u8; METHOD.salt_len()];
        let key = kdf::session_key(&master, &salt, METHOD).expect("выводится");
        let mut cipher = Cipher::new(METHOD, &key).expect("ключ подходит");

        let mut wire = salt;
        wire.extend_from_slice(&cipher.seal(&0xFFFFu16.to_be_bytes()).expect("шифруется"));
        server.write_all(&wire).await.expect("ушло");

        let mut got = [0u8; 1];
        let err = client
            .read_exact(&mut got)
            .await
            .expect_err("не по протоколу");
        assert!(
            err.to_string().contains("протокол такого не допускает"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_long_write_is_cut_into_chunks() {
        // Длина пишется двумя байтами с запасом на служебные биты: кусок
        // длиннее предела сервер не примет.
        let (mut client, mut server, _) = pair();
        let payload = vec![7u8; MAX_CHUNK + 1000];

        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.expect("ушло");
            client.flush().await.expect("сброшено");
        });

        // Первый кусок — ровно предел, второй — остаток.
        let mut head = vec![0u8; LENGTH_FRAME];
        server.read_exact(&mut head).await.expect("пришло");
        let mut body = vec![0u8; sealed_len(MAX_CHUNK)];
        server.read_exact(&mut body).await.expect("пришло");

        let mut head = vec![0u8; LENGTH_FRAME];
        server.read_exact(&mut head).await.expect("пришло");
        let mut body = vec![0u8; sealed_len(1000)];
        server.read_exact(&mut body).await.expect("пришло");

        writer.await.expect("задача");
    }
}
