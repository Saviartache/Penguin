//! Поток принятых соединений с их адресами.
//!
//! Стек не «слушает порт» в обычном смысле: он принимает **любое** соединение,
//! куда бы оно ни шло, — в этом и смысл перехвата. Поэтому вместо привычного
//! `bind` здесь просто очередь готовых соединений.

use std::net::SocketAddr;

use tokio::sync::mpsc;

use super::conn::TcpConnection;

/// Сколько принятых соединений держать, пока их не забрали.
///
/// Переполнение означает, что движок не успевает разбирать соединения. Новые
/// в этом случае не принимаются, и приложение видит обычную для перегруженной
/// сети задержку установления, а не растущую память клиента.
pub const ACCEPT_QUEUE: usize = 128;

/// Принятое соединение вместе с адресами.
#[derive(Debug)]
pub struct Accepted {
    /// Соединение.
    pub connection: TcpConnection,
    /// Откуда пришло.
    pub source: SocketAddr,
    /// Куда идёт.
    pub destination: SocketAddr,
}

/// Очередь принятых соединений.
#[derive(Debug)]
pub struct TcpListener {
    incoming: mpsc::Receiver<Accepted>,
}

impl TcpListener {
    /// Создаёт пару «очередь — отправитель».
    pub fn new() -> (Self, mpsc::Sender<Accepted>) {
        let (tx, rx) = mpsc::channel(ACCEPT_QUEUE);
        (Self { incoming: rx }, tx)
    }

    /// Ждёт следующее соединение.
    ///
    /// `None` — стек остановлен.
    pub async fn accept(&mut self) -> Option<Accepted> {
        self.incoming.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted(port: u16) -> Accepted {
        let source: SocketAddr = format!("10.0.0.2:{port}").parse().expect("адрес");
        let destination: SocketAddr = "93.184.216.34:443".parse().expect("адрес");
        let (connection, _ends) = TcpConnection::new(source, destination);
        Accepted {
            connection,
            source,
            destination,
        }
    }

    #[tokio::test]
    async fn hands_over_connections_in_order() {
        let (mut listener, sender) = TcpListener::new();

        sender.send(accepted(50000)).await.expect("отправлено");
        sender.send(accepted(50001)).await.expect("отправлено");

        assert_eq!(listener.accept().await.expect("есть").source.port(), 50000);
        assert_eq!(listener.accept().await.expect("есть").source.port(), 50001);
    }

    #[tokio::test]
    async fn stopping_the_stack_ends_the_stream() {
        let (mut listener, sender) = TcpListener::new();
        drop(sender);
        assert!(listener.accept().await.is_none());
    }

    #[test]
    fn queue_is_bounded() {
        // Без предела всплеск соединений превратился бы в рост памяти.
        const { assert!(ACCEPT_QUEUE > 0 && ACCEPT_QUEUE <= 1024) };
    }
}
