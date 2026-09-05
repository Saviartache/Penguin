//! Поток поверх уже подключённого сокета: связывает `obfs`, шифр и
//! `protocol` в одну пару `AsyncRead`/`AsyncWrite`.
//!
//! ```text
//!  запись:  protocol.client_pre_encrypt ─► шифр ─► obfs.client_encode ─► сокет
//!  чтение:  сокет ─► obfs.client_decode ─► шифр ─► protocol.client_post_decrypt
//! ```
//!
//! Адрес назначения и (для `auth_*`) разовый заголовок соединения уже ушли
//! к моменту, когда появляется `SsrStream`, — это часть рукопожатия в
//! [`crate::outbound`], а не этого файла. Здесь только то, что происходит
//! на каждый последующий вызов `poll_read`/`poll_write`.
//!
//! # Откуда в чтении второй шифр
//!
//! IV на чтение — это IV **сервера**, и он приходит в открытую самим
//! потоком, а не выбирается нами. Первые байты после снятия `obfs` копятся
//! в [`SsrStream::read_iv_buf`], пока их не наберётся ровно `method.iv_len()`
//! — точно так же, как `Encryptor.decrypt` в эталоне.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::crypto::Method;
use crate::crypto::cipher::{Keystream, build_decryptor};
use crate::error::ShadowsocksrError;
use crate::obfs::state::ObfsState;
use crate::protocol::state::ProtocolState;

/// Сколько байт брать из сокета за раз.
const READ_CHUNK: usize = 16 * 1024;

/// Поток ShadowsocksR поверх обычного соединения.
pub(crate) struct SsrStream<S> {
    io: S,
    method: Method,
    master_key: Vec<u8>,
    obfs: ObfsState,
    protocol: ProtocolState,
    /// Уже настроен на нужное направление и уже отправил IV — это сделал
    /// вызывающий (`outbound.rs`) перед тем, как отдать данные первому
    /// куску адреса назначения.
    write_cipher: Box<dyn Keystream>,
    read_cipher: Option<Box<dyn Keystream>>,
    read_iv_buf: Vec<u8>,
    out_buf: BytesMut,
    in_raw: BytesMut,
    in_ready: BytesMut,
}

impl<S> SsrStream<S> {
    /// Оборачивает соединение, в которое уже отправлены IV и адрес.
    ///
    /// `write_cipher` передаётся уже применённым к первому куску — это
    /// состояние (позиция ключевого потока) должно продолжиться, а не
    /// начаться заново.
    pub(crate) fn new(
        io: S,
        method: Method,
        master_key: Vec<u8>,
        obfs: ObfsState,
        protocol: ProtocolState,
        write_cipher: Box<dyn Keystream>,
    ) -> Self {
        // Метод `none` не шлёт IV вовсе — расшифровывать нечем, но и нечего:
        // шифр строится сразу, ждать нечего.
        let read_cipher = if method.iv_len() == 0 {
            build_decryptor(method, &master_key, &[]).ok()
        } else {
            None
        };

        Self {
            io,
            method,
            master_key,
            obfs,
            protocol,
            write_cipher,
            read_cipher,
            read_iv_buf: Vec::new(),
            out_buf: BytesMut::new(),
            in_raw: BytesMut::new(),
            in_ready: BytesMut::new(),
        }
    }
}

impl<S: AsyncWrite + Unpin> SsrStream<S> {
    /// Дописывает в сокет всё, что накопилось в [`Self::out_buf`].
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.out_buf.is_empty() {
            match Pin::new(&mut self.io).poll_write(cx, &self.out_buf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(written)) => self.out_buf.advance(written),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SsrStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut framed = this
            .protocol
            .client_pre_encrypt(buf, 0, None)
            .map_err(to_io_error)?;
        this.write_cipher.apply(&mut framed);
        let encoded = this.obfs.client_encode(&framed);
        this.out_buf.extend_from_slice(&encoded);

        // Насколько получится дописать прямо сейчас — не обязательно: вызов
        // считается принятым, как только вошёл в собственный буфер, а
        // хвост дотягивается следующим `poll_write` или `poll_flush`.
        let _ = this.poll_drain(cx);
        Poll::Ready(Ok(buf.len()))
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for SsrStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            if !this.in_ready.is_empty() {
                let take = this.in_ready.len().min(buf.remaining());
                buf.put_slice(&this.in_ready[..take]);
                this.in_ready.advance(take);
                return Poll::Ready(Ok(()));
            }

            // Сначала перерабатываем то, что уже лежит в `in_raw`: обфускация
            // могла отдать не всё сразу (например, ответ `http_simple` ещё
            // копит заголовки), и лишний поход в сокет здесь не нужен.
            match this.process_raw() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(err) => return Poll::Ready(Err(to_io_error(err))),
            }

            let before = this.in_raw.len();
            this.in_raw.resize(before + READ_CHUNK, 0);
            let mut chunk = ReadBuf::new(&mut this.in_raw[before..]);
            let result = Pin::new(&mut this.io).poll_read(cx, &mut chunk);
            let filled = chunk.filled().len();
            this.in_raw.truncate(before + filled);

            match result {
                Poll::Ready(Ok(())) if filled == 0 => {
                    return Poll::Ready(if this.has_pending_data() {
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

impl<S> SsrStream<S> {
    /// Перерабатывает всё, что можно получить из уже прочитанных байт, без
    /// обращения к сокету. `Ok(true)` — что-то продвинулось, стоит
    /// попробовать ещё раз; `Ok(false)` — дальше нужны новые байты из сокета.
    fn process_raw(&mut self) -> Result<bool, ShadowsocksrError> {
        let ciphertext = self.obfs.client_decode(&mut self.in_raw)?;
        if ciphertext.is_empty() {
            return Ok(false);
        }

        let mut body = ciphertext.as_slice();
        if self.read_cipher.is_none() {
            let need = self.method.iv_len() - self.read_iv_buf.len();
            let take = need.min(body.len());
            self.read_iv_buf.extend_from_slice(&body[..take]);
            body = &body[take..];
            if self.read_iv_buf.len() < self.method.iv_len() {
                return Ok(true); // IV ещё не набрался целиком
            }
            self.read_cipher = Some(build_decryptor(
                self.method,
                &self.master_key,
                &self.read_iv_buf,
            )?);
        }

        let mut plain = body.to_vec();
        if let Some(cipher) = &mut self.read_cipher {
            cipher.apply(&mut plain);
        }

        let decoded = self.protocol.client_post_decrypt(&plain)?;
        self.in_ready.extend_from_slice(&decoded);
        Ok(true)
    }

    /// Остался ли где-то в цепочке кусок, не дождавшийся продолжения — по
    /// нему обрыв соединения отличается от чистого конца.
    fn has_pending_data(&self) -> bool {
        !self.in_raw.is_empty()
            || (self.read_cipher.is_none() && !self.read_iv_buf.is_empty())
            || self.obfs.has_pending_data()
            || self.protocol.has_pending_data()
    }
}

/// Заворачивает ошибку протокола в `io::Error` для трейтов `tokio`.
///
/// Различие `Rejected`/`Malformed`/прочее важно для [`crate::error`] и
/// перевода в [`penguin_proto::error::ProtocolError`] — это происходит выше,
/// в `outbound.rs`, где сохраняется исходный тип ошибки. Здесь, на границе
/// с `tokio::io`, разница уже не нужна: обе означают «поток не по формату».
fn to_io_error(err: ShadowsocksrError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.to_string())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;
    use crate::crypto::cipher::build_encryptor;
    use crate::crypto::kdf;
    use crate::obfs::ObfsMethod;
    use crate::protocol::ProtocolMethod;

    const METHOD: Method = Method::Aes256Cfb;
    const PASSWORD: &str = "пароль от сервера";

    /// Собирает пару «клиент, сырой сокет», как будто адрес уже отправлен.
    fn client() -> (
        SsrStream<tokio::io::DuplexStream>,
        tokio::io::DuplexStream,
        Vec<u8>,
    ) {
        let (a, b) = duplex(1024 * 1024);
        let master = kdf::evp_bytes_to_key(PASSWORD.as_bytes(), METHOD.key_len());
        let iv = vec![3u8; METHOD.iv_len()];
        // IV на запись в `SsrStream` не входит: его отправляет `outbound.rs`
        // вместе с адресом назначения, ещё до того, как поток появляется на
        // свет. Здесь конструируем шифр напрямую — ровно так, как это делает
        // тот код, — и проверяем то, что происходит после.
        let write_cipher = build_encryptor(METHOD, &master, &iv).expect("шифр строится");

        let obfs = ObfsState::new(ObfsMethod::Plain, "example.com".into(), 8388, None, 0);
        let protocol = ProtocolState::new(ProtocolMethod::Origin, master.clone(), iv);

        (
            SsrStream::new(a, METHOD, master.clone(), obfs, protocol, write_cipher),
            b,
            master,
        )
    }

    /// Собирает то, что прислал бы сервер: свой IV и куски шифра под ним.
    fn from_server(master: &[u8], pieces: &[&[u8]]) -> Vec<u8> {
        let iv = vec![9u8; METHOD.iv_len()];
        let mut cipher = build_encryptor(METHOD, master, &iv).expect("шифр строится");
        let mut out = iv;
        for piece in pieces {
            let mut chunk = piece.to_vec();
            cipher.apply(&mut chunk);
            out.extend_from_slice(&chunk);
        }
        out
    }

    #[tokio::test]
    async fn a_write_reaches_the_socket_encrypted() {
        let (mut client, mut server, master) = client();
        client.write_all(b"hello").await.expect("пишется");
        client.flush().await.expect("сброшено");

        let mut wire = vec![0u8; 5];
        server.read_exact(&mut wire).await.expect("пришло");
        assert_ne!(wire, b"hello", "должно быть зашифровано");

        // Расшифровать тем же IV, что взят при постройке клиента (3u8;len).
        let iv = vec![3u8; METHOD.iv_len()];
        let mut cipher =
            crate::crypto::cipher::build_decryptor(METHOD, &master, &iv).expect("строится");
        cipher.apply(&mut wire);
        assert_eq!(wire, b"hello");
    }

    #[tokio::test]
    async fn what_the_server_sends_arrives_decrypted() {
        let (mut client, mut server, master) = client();
        server
            .write_all(&from_server(&master, &[b"first ", b"second"]))
            .await
            .expect("ушло");

        let mut got = [0u8; 12];
        client.read_exact(&mut got).await.expect("пришло");
        assert_eq!(&got, b"first second");
    }

    #[tokio::test]
    async fn a_reply_arriving_byte_by_byte_is_assembled() {
        let (mut client, mut server, master) = client();
        let wire = from_server(&master, &[b"payload"]);

        let reader = tokio::spawn(async move {
            let mut got = [0u8; 7];
            client.read_exact(&mut got).await.expect("пришло");
            got
        });

        for byte in wire {
            server.write_all(&[byte]).await.expect("ушло");
            server.flush().await.expect("сброшено");
        }
        assert_eq!(&reader.await.expect("задача"), b"payload");
    }

    #[tokio::test]
    async fn a_clean_close_before_any_data_is_not_an_error() {
        let (mut client, server, _) = client();
        drop(server);

        let mut got = Vec::new();
        client.read_to_end(&mut got).await.expect("чистый конец");
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn a_close_mid_iv_is_reported_as_an_error() {
        // Обрыв, пока IV сервера ещё не набрался целиком, — не то же самое,
        // что чистый конец: часть ключевого потока потеряна безвозвратно.
        let (mut client, mut server, _) = client();
        server.write_all(&[1, 2, 3]).await.expect("ушло");
        drop(server);

        let mut got = [0u8; 1];
        assert!(client.read_exact(&mut got).await.is_err());
    }
}
