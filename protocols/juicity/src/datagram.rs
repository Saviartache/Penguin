//! Канал датаграмм: один надёжный поток на всех адресатов.
//!
//! ```text
//!  заголовок потока   [3][адрес первого адресата]
//!  каждая датаграмма  [адрес][длина][данные]
//! ```
//!
//! Поток открывается первой посылкой: сервер ждёт в заголовке адрес.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_transport::addr::socks;
use penguin_transport::deadline;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::error::{JuicityError, JuicityResult};
use crate::frame::{proxy, udp};
use crate::link::Link;
use crate::pool::LinkPool;

/// Глубина очереди принятых датаграмм.
const QUEUE: usize = 512;

/// Канал датаграмм через сервер Juicity.
pub struct JuicityDatagram {
    pool: Arc<LinkPool>,
    /// Пусто — посылок ещё не было.
    outgoing: Mutex<Option<Outgoing>>,
    incoming: Mutex<mpsc::Receiver<(Bytes, SocketAddress)>>,
    /// Клон для задачи чтения.
    sender: mpsc::Sender<(Bytes, SocketAddress)>,
    reader: Mutex<Option<JoinHandle<()>>>,
}

/// Пишущая сторона вместе с соединением, которое держит эндпойнт.
struct Outgoing {
    _link: Arc<Link>,
    send: quinn::SendStream,
}

impl std::fmt::Debug for JuicityDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JuicityDatagram")
            .field("pool", &self.pool)
            .finish()
    }
}

impl JuicityDatagram {
    /// Заводит канал. Потока при этом не открывается.
    pub fn new(pool: Arc<LinkPool>) -> Self {
        let (sender, incoming) = mpsc::channel(QUEUE);
        Self {
            pool,
            outgoing: Mutex::new(None),
            incoming: Mutex::new(incoming),
            sender,
            reader: Mutex::new(None),
        }
    }

    /// Открывает поток датаграмм и объявляет первого адресата.
    async fn open(&self, first: &SocketAddress) -> Result<Outgoing, ProtocolError> {
        let stream = self.pool.open().await?;
        let (link, mut send, recv) = (stream.link, stream.send, stream.recv);

        let header = proxy::header(proxy::NET_UDP, first)?;
        deadline::handshake::<_, JuicityError>("заголовок датаграмм Juicity", async {
            send.write_all(&header)
                .await
                .map_err(|e| JuicityError::disconnected(e.to_string()))?;
            Ok(())
        })
        .await?;

        let reader = tokio::spawn(read_packets(
            Arc::clone(&link),
            BufReader::new(recv),
            self.sender.clone(),
        ));
        if let Some(previous) = self.reader.lock().await.replace(reader) {
            previous.abort();
        }
        Ok(Outgoing { _link: link, send })
    }
}

#[async_trait]
impl ProxyDatagram for JuicityDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let frame = udp::seal(target, &payload)?;

        let mut outgoing = self.outgoing.lock().await;
        if outgoing.is_none() {
            *outgoing = Some(self.open(target).await?);
        }
        let Some(io) = outgoing.as_mut() else {
            return Err(JuicityError::disconnected("поток датаграмм не открылся").into());
        };

        io.send
            .write_all(&frame)
            .await
            .map_err(|e| JuicityError::disconnected(e.to_string()))?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let mut incoming = self.incoming.lock().await;
        incoming
            .recv()
            .await
            .ok_or_else(|| JuicityError::disconnected("поток датаграмм закрылся").into())
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        if let Some(reader) = self.reader.lock().await.take() {
            reader.abort();
        }
        if let Some(mut outgoing) = self.outgoing.lock().await.take() {
            let _ = outgoing.send.finish();
        }
        Ok(())
    }
}

/// Читает датаграммы из потока, пока он жив.
async fn read_packets(
    _link: Arc<Link>,
    mut io: BufReader<quinn::RecvStream>,
    sender: mpsc::Sender<(Bytes, SocketAddress)>,
) {
    loop {
        let Ok(from) = read_address(&mut io).await else {
            return;
        };
        let mut len = [0_u8; 2];
        if io.read_exact(&mut len).await.is_err() {
            return;
        }
        let mut payload = vec![0_u8; usize::from(u16::from_be_bytes(len))];
        if !payload.is_empty() && io.read_exact(&mut payload).await.is_err() {
            return;
        }
        if sender.send((Bytes::from(payload), from)).await.is_err() {
            return;
        }
    }
}

/// Читает адрес датаграммы: длина по типу, разбор — общий `socks::decode`.
async fn read_address(io: &mut BufReader<quinn::RecvStream>) -> JuicityResult<SocketAddress> {
    let mut buf = [0_u8; udp::MAX_ADDRESS];
    io.read_exact(&mut buf[..1]).await?;
    let (head, tail) = match buf[0] {
        socks::ATYP_IPV4 => (1, 4 + 2),
        socks::ATYP_IPV6 => (1, 16 + 2),
        socks::ATYP_DOMAIN => {
            io.read_exact(&mut buf[1..2]).await?;
            (2, usize::from(buf[1]) + 2)
        }
        // Неизвестный тип отвергнет `decode`.
        _ => (1, 0),
    };
    io.read_exact(&mut buf[head..head + tail]).await?;
    match socks::decode(&buf[..head + tail])? {
        Some((address, _)) => Ok(address),
        None => Err(JuicityError::malformed("адрес датаграммы обрезан")),
    }
}
