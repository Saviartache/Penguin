//! Обфускация под TLS: первая посылка выглядит приветствием клиента.
//!
//! ```text
//!  ──► [22][03 01][длина] ClientHello, а данные лежат в расширении
//!  ──► [17 03 03][длина][данные]   дальше — «записи данных»
//!
//!  ◄── ответ сервера: два кадра, которые пропускаются целиком,
//!      дальше [тип][версия][длина][данные]
//! ```
//!
//! Настоящего TLS здесь нет: ни ключей, ни проверки, ни шифра. Есть форма
//! записей, и внутри неё едут байты протокола как есть — шифрует их сам
//! протокол. Тот, кто смотрит на размеры и первый байт, видит TLS; тот, кто
//! попробует с этим «сервером» договориться, не увидит ничего.
//!
//! # Про первый ответ
//!
//! У него пропускается 105 байт, а не три. Это не магия и не отступ «на
//! всякий случай»: сервер `simple-obfs` отвечает приветствием на 96 байт,
//! сменой шифра на 6 и только потом первой записью данных, у которой свои
//! три байта заголовка. Сумма и есть 105.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::{Buf, BytesMut};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Наибольшая запись. Столько же у настоящего TLS.
const RECORD: usize = 1 << 14;

/// Сколько байт пропустить в первом ответе.
const FIRST_SKIP: usize = 105;

/// Сколько байт пропустить в каждом следующем: тип и версия.
const NEXT_SKIP: usize = 3;

/// Сколько байт брать из сокета за раз.
const READ_CHUNK: usize = 16 * 1024;

/// Что читатель ждёт сейчас.
#[derive(Debug, Clone, Copy)]
enum Await {
    /// Пропустить столько байт заголовка.
    Skip(usize),
    /// Прочитать два байта длины.
    Length,
    /// Прочитать столько байт данных.
    Body(usize),
}

/// Соединение, прикрытое под TLS.
pub struct TlsObfs<S> {
    io: S,
    /// Имя узла в приветствии.
    server: String,
    /// Приветствие ещё не отправлено.
    fresh: bool,
    /// Что читается сейчас.
    step: Await,
    /// Зашифрованное, ещё не ушедшее в сокет.
    out: BytesMut,
    /// Сырое из сокета, ещё не разобранное.
    incoming: BytesMut,
    /// Разобранное, ещё не отданное читателю.
    ready: BytesMut,
}

impl<S> std::fmt::Debug for TlsObfs<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsObfs")
            .field("server", &self.server)
            .finish()
    }
}

impl<S> TlsObfs<S> {
    /// Оборачивает соединение. Ни одного байта при этом не уходит.
    pub fn new(io: S, server: impl Into<String>) -> Self {
        Self {
            io,
            server: server.into(),
            fresh: true,
            step: Await::Skip(FIRST_SKIP),
            out: BytesMut::new(),
            incoming: BytesMut::new(),
            ready: BytesMut::new(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsObfs<S> {
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

    /// Двигает разбор на один шаг. `false` — байт пока не хватает.
    fn take_step(&mut self) -> bool {
        match self.step {
            Await::Skip(count) => {
                if self.incoming.len() < count {
                    return false;
                }
                self.incoming.advance(count);
                self.step = Await::Length;
                true
            }
            Await::Length => {
                let Some(raw) = self.incoming.first_chunk::<2>().copied() else {
                    return false;
                };
                self.incoming.advance(2);
                self.step = Await::Body(usize::from(u16::from_be_bytes(raw)));
                true
            }
            Await::Body(0) => {
                self.step = Await::Skip(NEXT_SKIP);
                true
            }
            Await::Body(length) => {
                if self.incoming.is_empty() {
                    return false;
                }
                let take = self.incoming.len().min(length);
                self.ready.extend_from_slice(&self.incoming.split_to(take));
                self.step = if take == length {
                    Await::Skip(NEXT_SKIP)
                } else {
                    Await::Body(length - take)
                };
                true
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsObfs<S> {
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
            if this.take_step() {
                continue;
            }

            let before = this.incoming.len();
            this.incoming.resize(before + READ_CHUNK, 0);
            let mut chunk = ReadBuf::new(&mut this.incoming[before..]);

            let result = Pin::new(&mut this.io).poll_read(cx, &mut chunk);
            let filled = chunk.filled().len();
            this.incoming.truncate(before + filled);

            match result {
                Poll::Ready(Ok(())) if filled == 0 => {
                    // Оборванная посередине запись — потерянные данные, и
                    // отдать их как обычный конец значит показать неполный
                    // ответ полным.
                    return Poll::Ready(match this.step {
                        Await::Skip(NEXT_SKIP) => Ok(()),
                        _ => Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                    });
                }
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsObfs<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let take = buf.len().min(RECORD);
        if this.fresh {
            this.out
                .extend_from_slice(&hello(&this.server, &buf[..take]));
            this.fresh = false;
        } else {
            this.out.extend_from_slice(&record(&buf[..take]));
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

/// Обычная запись данных: тип, версия, длина, данные.
pub fn record(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + data.len());
    out.extend_from_slice(&[0x17, 0x03, 0x03]);
    out.extend_from_slice(&(data.len().min(RECORD) as u16).to_be_bytes());
    out.extend_from_slice(&data[..data.len().min(RECORD)]);
    out
}

/// Собирает приветствие клиента с данными внутри расширения.
///
/// Расширение — «билет сеанса» (`0x0023`): оно переменной длины и в настоящем
/// приветствии тоже бывает непустым, поэтому данные в нём не выглядят
/// чужеродно. Все прочие расширения — постоянные байты, списанные с обычного
/// клиента.
pub fn hello(server: &str, data: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut random = [0u8; 28];
    let mut session = [0u8; 32];
    rng.fill(&mut random);
    rng.fill(&mut session);

    let data_len = data.len().min(RECORD);
    let data = &data[..data_len];
    let server = server.as_bytes();

    let mut out = Vec::with_capacity(517 + data_len + server.len());

    // Запись рукопожатия, версия 1.0, длина.
    out.push(22);
    out.extend_from_slice(&[0x03, 0x01]);
    out.extend_from_slice(&((212 + data_len + server.len()) as u16).to_be_bytes());

    // Приветствие клиента: тип, трёхбайтовая длина, версия 1.2.
    out.push(1);
    out.push(0);
    out.extend_from_slice(&((208 + data_len + server.len()) as u16).to_be_bytes());
    out.extend_from_slice(&[0x03, 0x03]);

    // Случайное с отметкой времени, длина и номер сеанса.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs() as u32)
        .unwrap_or_default();
    out.extend_from_slice(&now.to_be_bytes());
    out.extend_from_slice(&random);
    out.push(32);
    out.extend_from_slice(&session);

    // Наборы шифров и сжатие — постоянные байты обычного клиента.
    out.extend_from_slice(&[0x00, 0x38]);
    out.extend_from_slice(&CIPHER_SUITES);
    out.extend_from_slice(&[0x01, 0x00]);

    // Длина расширений.
    out.extend_from_slice(&((79 + data_len + server.len()) as u16).to_be_bytes());

    // Билет сеанса: в нём и едут данные.
    out.extend_from_slice(&[0x00, 0x23]);
    out.extend_from_slice(&(data_len as u16).to_be_bytes());
    out.extend_from_slice(data);

    // Имя сервера.
    out.extend_from_slice(&[0x00, 0x00]);
    out.extend_from_slice(&((server.len() + 5) as u16).to_be_bytes());
    out.extend_from_slice(&((server.len() + 3) as u16).to_be_bytes());
    out.push(0);
    out.extend_from_slice(&(server.len() as u16).to_be_bytes());
    out.extend_from_slice(server);

    // Остальные расширения — тоже постоянные.
    out.extend_from_slice(&TAIL_EXTENSIONS);
    out
}

/// Наборы шифров обычного клиента.
const CIPHER_SUITES: [u8; 56] = [
    0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
    0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
    0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
    0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
];

/// Расширения после имени сервера: точки кривой, группы, подписи и два пустых.
const TAIL_EXTENSIONS: [u8; 66] = [
    0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, // ec_point_formats
    0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00,
    0x18, // supported_groups
    0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02,
    0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x02, 0x03, // signature_algorithms
    0x00, 0x16, 0x00, 0x00, // encrypt_then_mac
    0x00, 0x17, 0x00, 0x00, // extended_master_secret
];

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;

    fn pair() -> (TlsObfs<DuplexStream>, DuplexStream) {
        let (ours, theirs) = tokio::io::duplex(256 * 1024);
        (TlsObfs::new(ours, "bing.com"), theirs)
    }

    /// Собирает то, что прислал бы сервер обфускации.
    fn from_server(pieces: &[&[u8]]) -> Vec<u8> {
        // Приветствие сервера и смена шифра: клиент их пропускает не разбирая.
        let mut out = vec![0u8; FIRST_SKIP - NEXT_SKIP];
        for piece in pieces {
            out.extend_from_slice(&record(piece));
        }
        out
    }

    #[test]
    fn the_hello_declares_its_own_length_correctly() {
        // Длина записи считается трижды — в записи, в приветствии и в
        // расширениях, — и разойтись им нельзя: сервер читает по ней.
        for (server, data) in [("bing.com", &b"snell"[..]), ("a.io", &[][..])] {
            let hello = hello(server, data);
            let declared = u16::from_be_bytes([hello[3], hello[4]]);
            assert_eq!(
                usize::from(declared),
                hello.len() - 5,
                "запись врёт о своей длине"
            );

            let body = u16::from_be_bytes([hello[7], hello[8]]);
            assert_eq!(usize::from(body), hello.len() - 9, "приветствие врёт");
        }
    }

    #[test]
    fn the_hello_starts_like_a_real_one() {
        let hello = hello("bing.com", b"x");
        assert_eq!(hello[0], 22, "не рукопожатие");
        assert_eq!(&hello[1..3], &[0x03, 0x01], "не та версия записи");
        assert_eq!(hello[5], 1, "не приветствие клиента");
        assert_eq!(&hello[9..11], &[0x03, 0x03], "не та версия приветствия");
    }

    #[test]
    fn the_data_is_inside_the_session_ticket_and_the_name_after_it() {
        let hello = hello("bing.com", b"snell");
        let at = hello
            .windows(2)
            .position(|w| w == [0x00, 0x23])
            .expect("билет сеанса");
        assert_eq!(&hello[at + 2..at + 4], &5u16.to_be_bytes());
        assert_eq!(&hello[at + 4..at + 9], b"snell");
        assert!(
            hello.windows(8).any(|w| w == b"bing.com"),
            "имя сервера потерялось"
        );
    }

    #[tokio::test]
    async fn the_writes_after_the_first_are_plain_records() {
        let (mut obfs, mut peer) = pair();
        obfs.write_all(b"first").await.expect("пишется");
        obfs.write_all(b"second").await.expect("пишется");
        obfs.flush().await.expect("уходит");

        let mut got = vec![0u8; 1024];
        let read = peer.read(&mut got).await.expect("читается");
        got.truncate(read);

        let tail = &got[got.len() - 11..];
        assert_eq!(&tail[..3], &[0x17, 0x03, 0x03]);
        assert_eq!(&tail[3..5], &6u16.to_be_bytes());
        assert_eq!(&tail[5..], b"second");
    }

    #[tokio::test]
    async fn a_long_write_is_cut_into_records() {
        let (mut obfs, mut peer) = pair();
        let payload = vec![7u8; RECORD + 100];
        obfs.write_all(&payload).await.expect("пишется");
        obfs.flush().await.expect("уходит");

        // Приветствие с полной записью внутри, потом остаток своей записью.
        let mut head = vec![0u8; hello("bing.com", &payload[..RECORD]).len()];
        peer.read_exact(&mut head).await.expect("читается");

        let mut tail = vec![0u8; 5 + 100];
        peer.read_exact(&mut tail).await.expect("читается");
        assert_eq!(&tail[..3], &[0x17, 0x03, 0x03]);
        assert_eq!(&tail[3..5], &100u16.to_be_bytes());
    }

    #[tokio::test]
    async fn the_first_reply_skips_the_greeting_of_the_server() {
        let (mut obfs, mut peer) = pair();
        peer.write_all(&from_server(&[b"payload"]))
            .await
            .expect("пишется");

        let mut got = [0u8; 7];
        obfs.read_exact(&mut got).await.expect("читается");
        assert_eq!(&got, b"payload");
    }

    #[tokio::test]
    async fn the_records_after_the_first_are_unwrapped_too() {
        let (mut obfs, mut peer) = pair();
        peer.write_all(&from_server(&[b"one", b"two", b"three"]))
            .await
            .expect("пишется");

        let mut got = [0u8; 11];
        obfs.read_exact(&mut got).await.expect("читается");
        assert_eq!(&got, b"onetwothree");
    }

    #[tokio::test]
    async fn a_reply_arriving_in_pieces_is_assembled() {
        let (mut obfs, mut peer) = pair();
        let wire = from_server(&[b"payload"]);

        let reader = tokio::spawn(async move {
            let mut got = [0u8; 7];
            obfs.read_exact(&mut got).await.expect("читается");
            got
        });

        for byte in wire {
            peer.write_all(&[byte]).await.expect("пишется");
            peer.flush().await.expect("уходит");
        }
        assert_eq!(&reader.await.expect("задача"), b"payload");
    }

    #[tokio::test]
    async fn a_record_cut_in_half_is_an_error() {
        let (mut obfs, mut peer) = pair();
        let wire = from_server(&[b"payload"]);
        peer.write_all(&wire[..wire.len() - 3])
            .await
            .expect("пишется");
        drop(peer);

        let mut got = Vec::new();
        let err = obfs.read_to_end(&mut got).await.expect_err("оборвано");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn a_clean_end_between_records_is_not_an_error() {
        let (mut obfs, mut peer) = pair();
        peer.write_all(&from_server(&[b"payload"]))
            .await
            .expect("пишется");
        drop(peer);

        let mut got = Vec::new();
        obfs.read_to_end(&mut got).await.expect("чистый конец");
        assert_eq!(got, b"payload");
    }
}
