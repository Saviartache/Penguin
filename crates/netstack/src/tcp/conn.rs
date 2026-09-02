//! `AsyncRead`/`AsyncWrite` поверх сокета smoltcp.
//!
//! Сокеты smoltcp живут внутри цикла опроса и наружу не выдаются: у них нет
//! ни собственного пробуждения, ни владения, а трогать их из другой задачи
//! нельзя — весь стек однопоточный по построению.
//!
//! Поэтому наружу выдаётся пара очередей, а цикл перекладывает между ними и
//! сокетом. Приложение видит обычный поток, цикл — обычный сокет, и никто из
//! них не знает про другого.
//!
//! ```text
//!   приложение ──► сокет smoltcp ──► [очередь] ──► TcpConnection ──► движок
//!   приложение ◄── сокет smoltcp ◄── [очередь] ◄── TcpConnection ◄── движок
//! ```

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

/// Сколько блоков держать в очереди в каждую сторону.
///
/// Очередь — это единственное, что стоит между приложением и медленной
/// стороной; когда она заполняется, обратное давление доходит до окна TCP, и
/// приложение притормаживает само. Без предела оно бы просто копило данные в
/// памяти клиента.
pub const QUEUE_DEPTH: usize = 32;

/// Принятое соединение.
pub struct TcpConnection {
    /// Данные от приложения.
    incoming: mpsc::Receiver<Bytes>,
    /// Данные приложению.
    outgoing: PollSender<Bytes>,
    /// Непрочитанный остаток последнего блока.
    pending: Bytes,
    source: SocketAddr,
    destination: SocketAddr,
}

/// Концы очередей, остающиеся в цикле опроса.
pub struct ConnectionEnds {
    /// Куда цикл кладёт данные, пришедшие от приложения.
    pub to_engine: mpsc::Sender<Bytes>,
    /// Откуда цикл забирает данные для приложения.
    pub from_engine: mpsc::Receiver<Bytes>,
}

impl std::fmt::Debug for TcpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpConnection")
            .field("source", &self.source)
            .field("destination", &self.destination)
            .finish()
    }
}

impl TcpConnection {
    /// Создаёт пару «соединение — концы очередей».
    pub fn new(source: SocketAddr, destination: SocketAddr) -> (Self, ConnectionEnds) {
        let (to_engine, incoming) = mpsc::channel(QUEUE_DEPTH);
        let (to_app, from_engine) = mpsc::channel(QUEUE_DEPTH);

        let connection = Self {
            incoming,
            outgoing: PollSender::new(to_app),
            pending: Bytes::new(),
            source,
            destination,
        };
        (
            connection,
            ConnectionEnds {
                to_engine,
                from_engine,
            },
        )
    }

    /// Откуда соединение пришло.
    pub fn source(&self) -> SocketAddr {
        self.source
    }

    /// Куда оно идёт.
    pub fn destination(&self) -> SocketAddr {
        self.destination
    }
}

impl AsyncRead for TcpConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Блок мог не поместиться в буфер целиком — остаток лежит до
        // следующего чтения. Терять его нельзя: это данные приложения.
        if this.pending.is_empty() {
            match ready!(this.incoming.poll_recv(cx)) {
                Some(chunk) => this.pending = chunk,
                // Очередь закрыта — приложение закрыло соединение.
                None => return Poll::Ready(Ok(())),
            }
        }

        let take = this.pending.len().min(buf.remaining());
        buf.put_slice(&this.pending[..take]);
        this.pending = this.pending.slice(take..);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TcpConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        ready!(this.outgoing.poll_reserve(cx)).map_err(|_| closed())?;
        this.outgoing
            .send_item(Bytes::copy_from_slice(buf))
            .map_err(|_| closed())?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Отправленное уже в очереди; дальше его двигает цикл опроса, и
        // ждать здесь нечего.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Закрытие очереди цикл увидит как конец данных и закроет сокет на
        // запись — это и есть `FIN` для приложения.
        this.outgoing.close();
        Poll::Ready(Ok(()))
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "соединение закрыто")
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn addresses() -> (SocketAddr, SocketAddr) {
        (
            "10.0.0.2:50000".parse().expect("адрес"),
            "93.184.216.34:443".parse().expect("адрес"),
        )
    }

    #[tokio::test]
    async fn reads_what_the_loop_pushes() {
        let (source, destination) = addresses();
        let (mut connection, ends) = TcpConnection::new(source, destination);

        ends.to_engine
            .send(Bytes::from_static(b"hello"))
            .await
            .expect("отправлено");
        drop(ends.to_engine);

        let mut got = Vec::new();
        connection.read_to_end(&mut got).await.expect("прочитано");
        assert_eq!(got, b"hello");
    }

    #[tokio::test]
    async fn large_chunk_is_read_across_calls() {
        // Блок, не поместившийся в буфер, обязан дочитаться, а не пропасть.
        let (source, destination) = addresses();
        let (mut connection, ends) = TcpConnection::new(source, destination);

        ends.to_engine
            .send(Bytes::from(vec![7u8; 100]))
            .await
            .expect("отправлено");
        drop(ends.to_engine);

        let mut small = [0u8; 30];
        let mut total = 0;
        loop {
            let read = connection.read(&mut small).await.expect("прочитано");
            if read == 0 {
                break;
            }
            assert!(small[..read].iter().all(|b| *b == 7));
            total += read;
        }
        assert_eq!(total, 100);
    }

    #[tokio::test]
    async fn writes_reach_the_loop() {
        let (source, destination) = addresses();
        let (mut connection, mut ends) = TcpConnection::new(source, destination);

        connection.write_all(b"request").await.expect("записано");
        let chunk = ends.from_engine.recv().await.expect("получено");
        assert_eq!(&chunk[..], b"request");
    }

    #[tokio::test]
    async fn shutdown_closes_the_outgoing_queue() {
        // Закрытие очереди — это `FIN` для приложения; без него оно будет
        // ждать данных, которых больше не будет.
        let (source, destination) = addresses();
        let (mut connection, mut ends) = TcpConnection::new(source, destination);

        connection.write_all(b"bye").await.expect("записано");
        connection.shutdown().await.expect("закрыто");

        assert_eq!(
            &ends.from_engine.recv().await.expect("получено")[..],
            b"bye"
        );
        assert!(
            ends.from_engine.recv().await.is_none(),
            "очередь не закрылась"
        );
    }

    #[tokio::test]
    async fn writing_after_the_loop_is_gone_is_an_error() {
        let (source, destination) = addresses();
        let (mut connection, ends) = TcpConnection::new(source, destination);
        drop(ends);

        assert!(connection.write_all(b"x").await.is_err());
    }

    #[test]
    fn addresses_are_carried() {
        let (source, destination) = addresses();
        let (connection, _ends) = TcpConnection::new(source, destination);
        assert_eq!(connection.source(), source);
        assert_eq!(connection.destination(), destination);
    }
}
