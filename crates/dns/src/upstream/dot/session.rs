//! Одно соединение DoT на много запросов (RFC 7858 §3.3): ответы приходят в любом
//! порядке, своё находят по идентификатору, который сеанс выдаёт сам — у разных
//! приложений идентификаторы могут совпасть.

use std::collections::HashMap;
use std::future::Future;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::error::{DnsError, DnsResult};
use crate::message;

/// Запросов в очереди, пока соединение поднимается.
const QUEUE: usize = 64;

/// Наибольший ответ.
const MAX_RESPONSE: usize = 65_535;

/// Запрос и куда вернуть ответ.
pub(super) struct Query {
    pub(super) message: Vec<u8>,
    pub(super) reply: oneshot::Sender<Vec<u8>>,
}

/// Вход в сеанс; закрыт — сеанс кончился, нужен новый.
pub(super) type Session = mpsc::Sender<Query>;

/// Поднимает сеанс: соединение строится в задаче, а не в запросе, поэтому
/// истёкший срок запроса не бросает почти готовое соединение.
pub(super) fn spawn<S>(connect: impl Future<Output = DnsResult<S>> + Send + 'static) -> Session
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (session, queries) = mpsc::channel(QUEUE);
    tokio::spawn(async move {
        let outcome = match connect.await {
            Ok(stream) => serve(stream, queries).await,
            Err(err) => Err(err),
        };
        if let Err(err) = outcome {
            tracing::debug!(%err, "сеанс DoT закрыт");
        }
    });
    session
}

/// Пересылает запросы и раздаёт ответы, пока соединение живо.
async fn serve<S>(stream: S, mut queries: mpsc::Receiver<Query>) -> DnsResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let (frames_tx, mut frames) = mpsc::channel(QUEUE);
    // Отдельной задачей: чтение кадра в `select!` оборвалось бы на середине.
    let reading = tokio::spawn(read_frames(reader, frames_tx));
    let mut pending = Pending::default();

    let outcome = loop {
        tokio::select! {
            query = queries.recv() => {
                let Some(query) = query else { break Ok(()) };
                if let Err(err) = send(&mut writer, &mut pending, query).await {
                    break Err(err);
                }
            }
            frame = frames.recv() => match frame {
                Some(response) => pending.answer(response),
                None => break Err(DnsError::Upstream("сервер закрыл соединение".to_owned())),
            },
        }
    };
    reading.abort();
    outcome
}

async fn send<W: AsyncWrite + Unpin>(
    writer: &mut W,
    pending: &mut Pending,
    query: Query,
) -> DnsResult<()> {
    let Some(frame) = pending.admit(query)? else {
        return Ok(());
    };
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frames<R: AsyncRead + Unpin>(mut reader: R, frames: mpsc::Sender<Vec<u8>>) {
    loop {
        let mut length = [0u8; 2];
        if reader.read_exact(&mut length).await.is_err() {
            return;
        }
        let length = usize::from(u16::from_be_bytes(length));
        if length == 0 || length > MAX_RESPONSE {
            tracing::debug!(length, "DoT: нелепая длина ответа");
            return;
        }
        let mut response = vec![0u8; length];
        if reader.read_exact(&mut response).await.is_err() || frames.send(response).await.is_err() {
            return;
        }
    }
}

/// Ждущие ответа: свой идентификатор → идентификатор приложения и куда вернуть.
#[derive(Default)]
struct Pending {
    waiting: HashMap<u16, (u16, oneshot::Sender<Vec<u8>>)>,
    next: u16,
}

impl Pending {
    /// Кадр для отправки; `None` — запрос уже никому не нужен.
    fn admit(&mut self, query: Query) -> DnsResult<Option<Vec<u8>>> {
        if query.reply.is_closed() {
            return Ok(None);
        }
        let mut message = query.message;
        let Some(original) = message.first_chunk::<2>().map(|id| u16::from_be_bytes(*id)) else {
            return Err(DnsError::Malformed("запрос короче заголовка".to_owned()));
        };
        let length = u16::try_from(message.len())
            .map_err(|_| DnsError::Malformed("запрос длиннее 65 535 байт".to_owned()))?;

        // Брошенные запросы не копятся: их место займут новые.
        self.waiting.retain(|_, (_, reply)| !reply.is_closed());
        let id = self.free_id();
        message::set_id(&mut message, id);
        self.waiting.insert(id, (original, query.reply));

        let mut frame = Vec::with_capacity(message.len() + 2);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&message);
        Ok(Some(frame))
    }

    /// Возвращает ответ спросившему с его идентификатором; чужой ответ отбрасывается.
    fn answer(&mut self, mut response: Vec<u8>) {
        let Some(id) = response
            .first_chunk::<2>()
            .map(|id| u16::from_be_bytes(*id))
        else {
            return;
        };
        if let Some((original, reply)) = self.waiting.remove(&id) {
            message::set_id(&mut response, original);
            let _ = reply.send(response);
        }
    }

    fn free_id(&mut self) -> u16 {
        while self.waiting.contains_key(&self.next) {
            self.next = self.next.wrapping_add(1);
        }
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn ask(session: &Session, message: Vec<u8>) -> oneshot::Receiver<Vec<u8>> {
        let (reply, answer) = oneshot::channel();
        session
            .send(Query { message, reply })
            .await
            .expect("сеанс жив");
        answer
    }

    async fn read_frame<R: AsyncRead + Unpin>(server: &mut R) -> Vec<u8> {
        let mut length = [0u8; 2];
        server.read_exact(&mut length).await.expect("длина");
        let mut frame = vec![0u8; usize::from(u16::from_be_bytes(length))];
        server.read_exact(&mut frame).await.expect("кадр");
        frame
    }

    async fn write_frame<W: AsyncWrite + Unpin>(server: &mut W, frame: &[u8]) {
        let length = u16::try_from(frame.len()).expect("короткий");
        server
            .write_all(&length.to_be_bytes())
            .await
            .expect("длина");
        server.write_all(frame).await.expect("кадр");
    }

    // Два приложения с одним ID, сервер отвечает в обратном порядке.
    #[tokio::test]
    async fn answers_find_their_queries_over_one_connection() {
        let (client, mut server) = tokio::io::duplex(1024);
        let session = spawn(async move { Ok(client) });

        let first = ask(&session, vec![0x12, 0x34, b'a']).await;
        let second = ask(&session, vec![0x12, 0x34, b'b']).await;

        let one = read_frame(&mut server).await;
        let two = read_frame(&mut server).await;
        assert_ne!(one[..2], two[..2], "на проводе идентификаторы разные");
        write_frame(&mut server, &[two[0], two[1], b'B']).await;
        write_frame(&mut server, &[one[0], one[1], b'A']).await;

        assert_eq!(first.await.expect("ответ"), vec![0x12, 0x34, b'A']);
        assert_eq!(second.await.expect("ответ"), vec![0x12, 0x34, b'B']);
    }

    #[tokio::test]
    async fn a_closed_connection_closes_the_session() {
        let (client, server) = tokio::io::duplex(1024);
        let session = spawn(async move { Ok(client) });
        let answer = ask(&session, vec![0, 1, 2]).await;
        drop(server);

        assert!(answer.await.is_err(), "ответа не будет");
        session.closed().await;
    }

    #[tokio::test]
    async fn a_failed_connect_closes_the_session() {
        let session = spawn(async {
            Err::<tokio::io::DuplexStream, _>(DnsError::Upstream("нет".to_owned()))
        });
        session.closed().await;
    }

    #[test]
    fn abandoned_queries_do_not_hold_ids() {
        let mut pending = Pending::default();
        let (reply, answer) = oneshot::channel();
        let query = Query {
            message: vec![0, 0, 1],
            reply,
        };
        assert!(pending.admit(query).expect("кадр").is_some());
        drop(answer);

        let (reply, _answer) = oneshot::channel();
        let query = Query {
            message: vec![0, 0, 1],
            reply,
        };
        pending.admit(query).expect("кадр");
        assert_eq!(pending.waiting.len(), 1);
    }
}
