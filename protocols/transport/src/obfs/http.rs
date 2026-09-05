//! Обфускация под HTTP: первый запрос выглядит переходом на WebSocket.
//!
//! ```text
//!  ──► GET / HTTP/1.1
//!      Host: bing.com
//!      Upgrade: websocket
//!      ...
//!      <пустая строка>
//!      <первые байты протокола>
//!  ──► <дальше байты протокола как есть>
//!
//!  ◄── HTTP/1.1 101 ...
//!      <пустая строка>
//!      <байты протокола>
//! ```
//!
//! Всё, что до пустой строки, — украшение: сервер его не разбирает, а ищет в
//! потоке `\r\n\r\n` и берёт то, что после. Поэтому заголовки можно писать
//! какие угодно, лишь бы разговор был похож на обычный.
//!
//! # Чем мы отличаемся от `simple-obfs`
//!
//! Ключ `Sec-WebSocket-Key` записывается обычным base64 с дополнением, а не
//! тем, что для URL. Настоящий браузер пишет именно так; читать это поле
//! всё равно некому, а похожим на браузер быть полезнее, чем похожим на
//! `simple-obfs`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Конец заголовков.
const END: &[u8] = b"\r\n\r\n";

/// Сколько байт заголовков принимать, прежде чем считать, что это не HTTP.
///
/// Ответ обфускации короткий; всё, что длиннее, — либо не тот сервер, либо
/// попытка заставить нас копить память.
const MAX_HEAD: usize = 16 * 1024;

/// Сколько байт брать из сокета за раз, пока идут заголовки.
const READ_CHUNK: usize = 4 * 1024;

/// Соединение, прикрытое под HTTP.
pub struct HttpObfs<S> {
    io: S,
    /// Имя узла в запросе.
    host: String,
    /// Порт: в `Host` он попадает, только если не восьмидесятый.
    port: u16,
    /// Заголовок запроса и первые данные, ещё не ушедшие в сокет.
    out: BytesMut,
    /// Запрос ещё не отправлен.
    fresh: bool,
    /// Заголовки ответа ещё не сняты.
    heading: bool,
    /// Прочитанное после заголовков, ещё не отданное читателю.
    ready: BytesMut,
}

impl<S> std::fmt::Debug for HttpObfs<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpObfs")
            .field("host", &self.host)
            .field("port", &self.port)
            .finish()
    }
}

impl<S> HttpObfs<S> {
    /// Оборачивает соединение. Ни одного байта при этом не уходит.
    pub fn new(io: S, host: impl Into<String>, port: u16) -> Self {
        Self {
            io,
            host: host.into(),
            port,
            out: BytesMut::new(),
            fresh: true,
            heading: true,
            ready: BytesMut::new(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> HttpObfs<S> {
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
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for HttpObfs<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.heading {
            if !this.ready.is_empty() {
                let take = this.ready.len().min(buf.remaining());
                buf.put_slice(&this.ready[..take]);
                this.ready.advance(take);
                return Poll::Ready(Ok(()));
            }
            return Pin::new(&mut this.io).poll_read(cx, buf);
        }

        loop {
            if let Some(at) = find(&this.ready, END) {
                this.ready.advance(at + END.len());
                this.heading = false;
                // Хвост уже прочитан вместе с заголовками: отдать его надо
                // тем же чтением, иначе первые байты ответа пропадут.
                let take = this.ready.len().min(buf.remaining());
                buf.put_slice(&this.ready[..take]);
                this.ready.advance(take);
                return Poll::Ready(Ok(()));
            }
            if this.ready.len() > MAX_HEAD {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ответ без конца заголовков: на том конце не обфускация",
                )));
            }

            let before = this.ready.len();
            this.ready.resize(before + READ_CHUNK, 0);
            let mut chunk = ReadBuf::new(&mut this.ready[before..]);

            let result = Pin::new(&mut this.io).poll_read(cx, &mut chunk);
            let filled = chunk.filled().len();
            this.ready.truncate(before + filled);

            match result {
                Poll::Ready(Ok(())) if filled == 0 => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::UnexpectedEof)));
                }
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for HttpObfs<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if !this.fresh {
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
            return Pin::new(&mut this.io).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Заголовок и первые данные уходят вместе: `Content-Length` объявляет
        // ровно их, и разрывать их значит слать запрос без тела.
        this.out
            .extend_from_slice(&request(&this.host, this.port, buf.len()));
        this.out.extend_from_slice(buf);
        this.fresh = false;

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

/// Собирает заголовок запроса.
pub fn request(host: &str, port: u16, body: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 16];
    rng.fill(&mut key);

    let authority = if port == 80 {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };

    format!(
        "GET / HTTP/1.1\r\n\
         Host: {authority}\r\n\
         User-Agent: curl/7.{}.{}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Content-Length: {body}\r\n\
         \r\n",
        rng.gen_range(0..54),
        rng.gen_range(0..2),
        penguin_core::base64::encode(&key),
    )
    .into_bytes()
}

/// Где в `haystack` начинается `needle`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;

    fn pair() -> (HttpObfs<DuplexStream>, DuplexStream) {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        (HttpObfs::new(ours, "bing.com", 443), theirs)
    }

    #[tokio::test]
    async fn the_first_write_looks_like_a_request_and_carries_the_data() {
        let (mut obfs, mut peer) = pair();
        obfs.write_all(b"snell").await.expect("пишется");
        obfs.flush().await.expect("уходит");

        let mut got = vec![0u8; 512];
        let read = peer.read(&mut got).await.expect("читается");
        got.truncate(read);
        let text = String::from_utf8_lossy(&got);

        assert!(text.starts_with("GET / HTTP/1.1\r\n"), "{text}");
        assert!(text.contains("Upgrade: websocket\r\n"), "{text}");
        assert!(text.contains("Content-Length: 5\r\n"), "{text}");
        assert!(text.ends_with("\r\n\r\nsnell"), "данные не в теле: {text}");
    }

    #[tokio::test]
    async fn the_port_shows_up_in_the_host_header_unless_it_is_eighty() {
        let head = String::from_utf8(request("bing.com", 443, 0)).expect("текст");
        assert!(head.contains("Host: bing.com:443\r\n"), "{head}");

        let head = String::from_utf8(request("bing.com", 80, 0)).expect("текст");
        assert!(head.contains("Host: bing.com\r\n"), "{head}");
        assert!(!head.contains("bing.com:80"), "{head}");
    }

    #[tokio::test]
    async fn the_writes_after_the_first_go_out_as_they_are() {
        let (mut obfs, mut peer) = pair();
        obfs.write_all(b"first").await.expect("пишется");
        obfs.write_all(b"second").await.expect("пишется");
        obfs.flush().await.expect("уходит");

        let mut got = vec![0u8; 1024];
        let read = peer.read(&mut got).await.expect("читается");
        got.truncate(read);
        assert!(got.ends_with(b"firstsecond"), "второй кусок обёрнут");
    }

    #[tokio::test]
    async fn the_headers_of_the_reply_are_stripped() {
        let (mut obfs, mut peer) = pair();
        peer.write_all(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nданные".as_bytes(),
        )
        .await
        .expect("пишется");

        let mut got = vec![0u8; "данные".len()];
        obfs.read_exact(&mut got).await.expect("читается");
        assert_eq!(got, "данные".as_bytes());
    }

    #[tokio::test]
    async fn a_reply_arriving_in_pieces_is_assembled() {
        let (mut obfs, mut peer) = pair();
        let wire = b"HTTP/1.1 101 Switching Protocols\r\n\r\npayload";

        let reader = tokio::spawn(async move {
            let mut got = [0u8; 7];
            obfs.read_exact(&mut got).await.expect("читается");
            got
        });

        for byte in wire {
            peer.write_all(&[*byte]).await.expect("пишется");
            peer.flush().await.expect("уходит");
        }
        assert_eq!(&reader.await.expect("задача"), b"payload");
    }

    #[tokio::test]
    async fn a_reply_that_never_ends_its_headers_is_refused() {
        // Иначе сервер, шлющий заголовки бесконечно, набивал бы нам память.
        let (mut obfs, mut peer) = pair();
        let writer = tokio::spawn(async move {
            let noise = vec![b'x'; 4096];
            for _ in 0..8 {
                if peer.write_all(&noise).await.is_err() {
                    return;
                }
            }
        });

        let mut got = [0u8; 1];
        let err = obfs.read_exact(&mut got).await.expect_err("не обфускация");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        writer.abort();
    }

    #[tokio::test]
    async fn a_reply_cut_before_the_headers_end_is_an_error() {
        let (mut obfs, mut peer) = pair();
        peer.write_all(b"HTTP/1.1 101 Switching")
            .await
            .expect("пишется");
        drop(peer);

        let mut got = [0u8; 1];
        let err = obfs.read_exact(&mut got).await.expect_err("оборвано");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
