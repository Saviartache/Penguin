//! Запрос на соединение: сообщение в очередь цикла, ответ приходит после рукопожатия.

use std::net::SocketAddr;

use tokio::sync::{mpsc, oneshot};

use crate::tcp::conn::TcpConnection;

/// Почему соединение не открылось.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectError {
    /// Другая сторона ответила отказом.
    #[error("соединение отвергнуто: {0}")]
    Refused(SocketAddr),

    /// Ответа не было вовсе (в отличие от отказа: до той стороны не дошло).
    #[error("нет ответа от {0}")]
    TimedOut(SocketAddr),

    /// У интерфейса нет адреса того же семейства, что у назначения.
    #[error("у интерфейса нет адреса для {0}")]
    NoAddress(SocketAddr),

    /// Свободных портов не осталось.
    #[error("свободных портов не осталось")]
    NoPorts,

    /// Стек остановлен.
    #[error("стек остановлен")]
    Stopped,
}

/// Запрос, который цикл забирает из очереди.
pub struct Request {
    /// Куда идти.
    pub destination: SocketAddr,
    /// Куда положить ответ.
    pub reply: oneshot::Sender<Result<TcpConnection, ConnectError>>,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("destination", &self.destination)
            .finish()
    }
}

/// Чем движок открывает соединения через тоннель; клонируется дёшево.
#[derive(Debug, Clone)]
pub struct Connector {
    requests: mpsc::Sender<Request>,
}

impl Connector {
    /// Заводит пару «связь наружу — очередь внутрь».
    pub fn new(depth: usize) -> (Self, mpsc::Receiver<Request>) {
        let (requests, incoming) = mpsc::channel(depth);
        (Self { requests }, incoming)
    }

    /// Открывает соединение и ждёт рукопожатия; остановленный стек даёт `Stopped`.
    pub async fn connect(&self, destination: SocketAddr) -> Result<TcpConnection, ConnectError> {
        let (reply, answer) = oneshot::channel();
        self.requests
            .send(Request { destination, reply })
            .await
            .map_err(|_| ConnectError::Stopped)?;
        answer.await.map_err(|_| ConnectError::Stopped)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> SocketAddr {
        "93.184.216.34:443".parse().expect("адрес")
    }

    #[tokio::test]
    async fn a_request_reaches_the_loop_with_its_destination() {
        let (connector, mut incoming) = Connector::new(4);
        tokio::spawn(async move {
            let _ = connector.connect(address()).await;
        });

        let request = incoming.recv().await.expect("запрос дошёл");
        assert_eq!(request.destination, address());
    }

    #[tokio::test]
    async fn a_dead_loop_answers_at_once_instead_of_hanging() {
        let (connector, incoming) = Connector::new(4);
        drop(incoming);
        assert_eq!(
            connector.connect(address()).await.unwrap_err(),
            ConnectError::Stopped
        );
    }

    #[tokio::test]
    async fn a_dropped_reply_is_not_a_hang_either() {
        let (connector, mut incoming) = Connector::new(4);
        tokio::spawn(async move {
            let request = incoming.recv().await.expect("запрос");
            drop(request);
        });
        assert_eq!(
            connector.connect(address()).await.unwrap_err(),
            ConnectError::Stopped
        );
    }

    #[test]
    fn silence_and_refusal_are_told_apart() {
        assert_ne!(
            ConnectError::Refused(address()),
            ConnectError::TimedOut(address())
        );
    }
}
