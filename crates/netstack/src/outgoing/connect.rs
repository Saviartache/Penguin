//! Запрос на соединение и ответ на него.
//!
//! Сокеты smoltcp живут внутри цикла опроса и наружу не выдаются — как и на
//! входящей стороне. Поэтому «открой соединение» — это сообщение в очередь, а
//! не вызов: цикл заведёт сокет, дождётся рукопожатия и пришлёт готовый поток
//! обратно.
//!
//! ```text
//!   движок ──запрос──► [очередь] ──► цикл ──► сокет ──► сеть
//!   движок ◄─ответ────────────────── цикл    (когда рукопожатие прошло)
//! ```

use std::net::SocketAddr;

use tokio::sync::{mpsc, oneshot};

use crate::tcp::conn::TcpConnection;

/// Почему соединение не открылось.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectError {
    /// Другая сторона ответила отказом.
    #[error("соединение отвергнуто: {0}")]
    Refused(SocketAddr),

    /// Ответа не было вовсе.
    ///
    /// Отдельно от отказа: отказ означает, что там кто-то есть и он сказал
    /// «нет», а молчание — что до него не дошло. Решения по ним разные.
    #[error("нет ответа от {0}")]
    TimedOut(SocketAddr),

    /// У интерфейса нет адреса того же семейства, что у назначения.
    ///
    /// Сервер выдал только IPv4, а идти надо на адрес IPv6 (или наоборот).
    /// Это не сбой сети: с таким интерфейсом туда не дойти вовсе.
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

/// Чем движок открывает соединения через тоннель.
///
/// Клонируется дёшево: внутри отправитель очереди. Одного хватает на весь
/// профиль — соединения открываются по одному и параллельно.
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

    /// Открывает соединение и ждёт, пока рукопожатие пройдёт.
    ///
    /// Ошибка приходит и от цикла, и от самого канала: остановленный стек
    /// роняет и очередь, и ответ, и оба случая означают одно.
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
        // Иначе движок ждал бы ответа от очереди, которую некому читать, —
        // и подключение выглядело бы вечно длящимся.
        let (connector, incoming) = Connector::new(4);
        drop(incoming);
        assert_eq!(
            connector.connect(address()).await.unwrap_err(),
            ConnectError::Stopped
        );
    }

    #[tokio::test]
    async fn a_dropped_reply_is_not_a_hang_either() {
        // Цикл мог взять запрос и умереть, не ответив.
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
        // Отказ означает, что там кто-то есть; молчание — что не дошло.
        assert_ne!(
            ConnectError::Refused(address()),
            ConnectError::TimedOut(address())
        );
    }
}
