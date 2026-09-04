//! Канал датаграмм: по потоку на адресата.
//!
//! # Откуда такая сложность
//!
//! У VLESS адрес назначения назван **один раз**, в заголовке запроса. Значит,
//! поток обслуживает ровно одного адресата, а канал датаграмм приложения —
//! это сколько угодно адресатов сразу. Приходится держать их все.
//!
//! ```text
//!   send_to(A) ──► поток A ──► задача чтения ─┐
//!   send_to(B) ──► поток B ──► задача чтения ─┼──► очередь ──► recv_from
//!   send_to(C) ──► поток C ──► задача чтения ─┘
//! ```
//!
//! У Trojan и SOCKS5 этого нет: там адрес стоит на каждой посылке, и хватает
//! одного потока. Разница видна не в скорости, а в том, сколько всего может
//! пойти не так, — поэтому каждая её часть названа ниже.
//!
//! # Что здесь решается
//!
//! **Кто ответил.** Ответ приходит из потока, а не с адресом внутри, — значит,
//! адресата помнит тот, кто этот поток открыл. Задача чтения кладёт его в
//! очередь вместе с данными.
//!
//! **Когда закрывать.** Приложение о конце UDP-сессии не сообщает: у неё нет
//! конца. Потоки живут, пока живёт канал, и закрываются вместе с ним —
//! иначе каждый запрос DNS оставлял бы за собой открытое соединение.
//!
//! **Сколько их.** Один заражённый узел может опросить тысячу адресов; предел
//! [`MAX_SESSIONS`] — не оптимизация, а то, что отделяет медленный клиент от
//! исчерпанной памяти.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_proto::stream::ProxyStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::connector::Connector;
use crate::error::VlessError;
use crate::frame::request::CMD_UDP;
use crate::frame::udp;

/// Сколько адресатов канал держит одновременно.
///
/// Больше — это уже не приложение, а перебор адресов: у каждого потока свой
/// сокет, своё рукопожатие TLS и своя задача.
pub const MAX_SESSIONS: usize = 256;

/// Сколько ответов держать в очереди, пока их не забрали.
const QUEUE: usize = 512;

/// Сколько байт брать из потока за раз.
const CHUNK: usize = 16 * 1024;

/// Канал датаграмм через сервер VLESS.
pub struct VlessDatagram {
    connector: Arc<Connector>,
    /// Потоки по адресатам: пишущая половина и задача, читающая ответы.
    sessions: Mutex<HashMap<SocketAddress, Session>>,
    /// Ответы со всех потоков сразу.
    incoming: Mutex<mpsc::Receiver<(Bytes, SocketAddress)>>,
    /// Его отдают задачам чтения.
    sender: mpsc::Sender<(Bytes, SocketAddress)>,
}

/// Один адресат: куда писать и кто читает.
struct Session {
    send: WriteHalf<Box<dyn ProxyStream>>,
    reader: JoinHandle<()>,
}

impl std::fmt::Debug for VlessDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessDatagram")
            .field("connector", &self.connector)
            .finish()
    }
}

impl VlessDatagram {
    /// Собирает канал. Потоков при этом не открывается: их заводит первая
    /// посылка каждому адресату.
    pub fn new(connector: Arc<Connector>) -> Self {
        let (sender, incoming) = mpsc::channel(QUEUE);
        Self {
            connector,
            sessions: Mutex::new(HashMap::new()),
            incoming: Mutex::new(incoming),
            sender,
        }
    }
}

#[async_trait]
impl ProxyDatagram for VlessDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let frame = udp::encode(&payload).map_err(ProtocolError::from)?;
        let mut sessions = self.sessions.lock().await;

        if !sessions.contains_key(target) {
            if sessions.len() >= MAX_SESSIONS {
                return Err(ProtocolError::Unsupported(
                    "больше адресатов в одном канале VLESS не помещается",
                ));
            }

            let io = self.connector.open(CMD_UDP, target).await?;
            let (recv, send) = tokio::io::split(io);
            let reader = tokio::spawn(read_replies(recv, target.clone(), self.sender.clone()));
            sessions.insert(target.clone(), Session { send, reader });
        }

        let Some(session) = sessions.get_mut(target) else {
            return Err(VlessError::Disconnected("поток до адресата пропал".into()).into());
        };

        // Обрыв одного адресата — это не конец канала: остальные живут. Поток
        // убирается, и следующая посылка откроет его заново.
        if let Err(err) = write_frame(&mut session.send, &frame).await {
            if let Some(session) = sessions.remove(target) {
                session.reader.abort();
            }
            return Err(err.into());
        }
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let mut incoming = self.incoming.lock().await;
        incoming.recv().await.ok_or_else(|| {
            // Отправитель жив, пока жив сам канал: пустая очередь означает,
            // что канал закрывают.
            VlessError::Disconnected("канал датаграмм закрыт".to_owned()).into()
        })
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        let mut sessions = self.sessions.lock().await;
        for (_, mut session) in sessions.drain() {
            // Сначала задача, потом поток: иначе она успеет прочитать конец
            // потока и сообщить о нём как об обрыве.
            session.reader.abort();
            let _ = session.send.shutdown().await;
        }
        Ok(())
    }
}

impl Drop for VlessDatagram {
    fn drop(&mut self) {
        // `close` зовут не всегда — например, когда направление снимают
        // целиком. Задача чтения ждёт на сокете и сама не кончится никогда:
        // без этого каждый запрос DNS оставлял бы за собой живую задачу.
        if let Ok(sessions) = self.sessions.try_lock() {
            for session in sessions.values() {
                session.reader.abort();
            }
        }
    }
}

/// Пишет кадр в поток адресата.
async fn write_frame(
    send: &mut WriteHalf<Box<dyn ProxyStream>>,
    frame: &[u8],
) -> Result<(), VlessError> {
    send.write_all(frame).await?;
    send.flush().await?;
    Ok(())
}

/// Читает ответы одного адресата и складывает их в общую очередь.
///
/// Заканчивается сама, когда поток закрылся или очередь никому не нужна.
async fn read_replies(
    mut io: ReadHalf<Box<dyn ProxyStream>>,
    source: SocketAddress,
    sender: mpsc::Sender<(Bytes, SocketAddress)>,
) {
    let mut buffer = BytesMut::with_capacity(CHUNK);

    loop {
        match udp::decode(&buffer) {
            Ok(Some((payload, used))) => {
                let _ = buffer.split_to(used);
                if sender.send((payload, source.clone())).await.is_err() {
                    // Канал закрыли — читать больше некому.
                    return;
                }
                continue;
            }
            Ok(None) => {}
            Err(err) => {
                tracing::debug!(%source, %err, "поток датаграмм разъехался");
                return;
            }
        }

        let before = buffer.len();
        buffer.resize(before + CHUNK, 0);
        let read = match io.read(&mut buffer[before..]).await {
            Ok(read) => read,
            Err(err) => {
                tracing::debug!(%source, %err, "поток датаграмм оборвался");
                return;
            }
        };
        buffer.truncate(before + read);

        if read == 0 {
            // Конец потока для UDP — это не ошибка: адресат просто больше не
            // отвечает. Молчание здесь честнее выдуманной ошибки.
            tracing::debug!(%source, "поток датаграмм закрыт сервером");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replies_carry_the_address_of_the_stream_they_came_from() {
        // Адреса внутри ответа нет: помнит его тот, кто открыл поток.
        let (client, mut server) = tokio::io::duplex(4096);
        let (sender, mut incoming) = mpsc::channel(8);
        let source = SocketAddress::domain("dns.example.com", 53);

        let boxed: Box<dyn ProxyStream> = Box::new(client);
        let (recv, _send) = tokio::io::split(boxed);
        let reader = tokio::spawn(read_replies(recv, source.clone(), sender));

        server
            .write_all(&udp::encode(b"answer").expect("собирается"))
            .await
            .expect("ушло");

        let (payload, from) = incoming.recv().await.expect("пришло");
        assert_eq!(&payload[..], b"answer");
        assert_eq!(from, source);
        reader.abort();
    }

    #[tokio::test]
    async fn two_replies_in_one_chunk_are_read_one_by_one() {
        let (client, mut server) = tokio::io::duplex(4096);
        let (sender, mut incoming) = mpsc::channel(8);
        let source = SocketAddress::domain("dns.example.com", 53);

        let boxed: Box<dyn ProxyStream> = Box::new(client);
        let (recv, _send) = tokio::io::split(boxed);
        let reader = tokio::spawn(read_replies(recv, source, sender));

        let mut wire = udp::encode(b"one").expect("собирается");
        wire.extend_from_slice(&udp::encode(b"two").expect("собирается"));
        server.write_all(&wire).await.expect("ушло");

        assert_eq!(&incoming.recv().await.expect("пришло").0[..], b"one");
        assert_eq!(&incoming.recv().await.expect("пришло").0[..], b"two");
        reader.abort();
    }

    #[tokio::test]
    async fn a_closed_stream_ends_the_reader_without_an_error() {
        // Конец потока для UDP — это не ошибка: адресат просто больше не
        // отвечает, и выдумывать ошибку тут не о чем.
        let (client, server) = tokio::io::duplex(4096);
        let (sender, mut incoming) = mpsc::channel(8);

        let boxed: Box<dyn ProxyStream> = Box::new(client);
        let (recv, _send) = tokio::io::split(boxed);
        let reader = tokio::spawn(read_replies(
            recv,
            SocketAddress::domain("dns.example.com", 53),
            sender,
        ));
        drop(server);

        reader.await.expect("задача кончилась сама");
        assert!(incoming.recv().await.is_none());
    }
}
