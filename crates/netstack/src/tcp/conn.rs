//! `AsyncRead`/`AsyncWrite` поверх сокета smoltcp.
//!
//! Сокеты живут внутри цикла опроса; наружу выдаётся пара очередей, между
//! которыми и сокетом данные перекладывает цикл.
//!
//! ```text
//!   приложение ──► сокет smoltcp ──► [очередь] ──► TcpConnection ──► движок
//!   приложение ◄── сокет smoltcp ◄── [очередь] ◄── TcpConnection ◄── движок
//! ```

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::PollSender;

/// Глубина очереди в каждую сторону; заполнение даёт обратное давление до окна TCP.
pub const QUEUE_DEPTH: usize = 32;

/// Принятое соединение.
pub struct TcpConnection {
    /// Данные от приложения.
    incoming: mpsc::Receiver<Bytes>,
    /// Данные приложению.
    outgoing: PollSender<Bytes>,
    /// Непрочитанный остаток последнего блока.
    pending: Bytes,
    /// Будит цикл стека, когда у соединения появилась работа.
    wake: Option<Arc<Notify>>,
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
            wake: None,
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

    /// Подключает пробуждение цикла стека.
    pub(crate) fn with_wake(mut self, wake: Arc<Notify>) -> Self {
        self.wake = Some(wake);
        self
    }

    /// Откуда соединение пришло.
    pub fn source(&self) -> SocketAddr {
        self.source
    }

    /// Куда оно идёт.
    pub fn destination(&self) -> SocketAddr {
        self.destination
    }

    fn wake(&self) {
        if let Some(wake) = &self.wake {
            wake.notify_one();
        }
    }
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        self.wake();
    }
}

impl AsyncRead for TcpConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if this.pending.is_empty() {
            match ready!(this.incoming.poll_recv(cx)) {
                Some(chunk) => {
                    this.pending = chunk;
                    // Очередь была полна: цикл держит блок и ждёт места.
                    if this.incoming.len() + 1 >= QUEUE_DEPTH {
                        this.wake();
                    }
                }
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
        this.wake();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    // Закрытие очереди цикл видит как конец данных и шлёт `FIN`.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.outgoing.close();
        this.wake();
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
    async fn writes_wake_the_loop() {
        let (source, destination) = addresses();
        let (connection, _ends) = TcpConnection::new(source, destination);
        let wake = Arc::new(Notify::new());
        let mut connection = connection.with_wake(Arc::clone(&wake));

        connection.write_all(b"x").await.expect("записано");
        tokio::time::timeout(std::time::Duration::from_secs(1), wake.notified())
            .await
            .expect("цикл не разбужен");
    }

    #[tokio::test]
    async fn shutdown_closes_the_outgoing_queue() {
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
