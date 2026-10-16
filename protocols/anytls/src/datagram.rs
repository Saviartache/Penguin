//! Канал датаграмм: один поток на всех адресатов.
//!
//! `udp-over-tcp` v2 ([`crate::uot`]): один поток к особому имени, адрес на
//! каждой датаграмме. Поток открывается первой посылкой: в заголовке нужен адрес.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_transport::addr::socks;
use penguin_transport::deadline;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::error::{AnyTlsError, AnyTlsResult};
use crate::pool::SessionPool;
use crate::stream::AnyTlsStream;
use crate::uot;

/// Сколько датаграмм держать в очереди, пока их не забрали.
const QUEUE: usize = 512;

/// Канал датаграмм через сервер AnyTLS.
pub struct AnyTlsDatagram {
    pool: Arc<SessionPool>,
    /// Пишущая половина потока; пусто до первой посылки.
    outgoing: Mutex<Option<WriteHalf<AnyTlsStream>>>,
    incoming: Mutex<mpsc::Receiver<(Bytes, SocketAddress)>>,
    /// Отдаётся задаче чтения.
    sender: mpsc::Sender<(Bytes, SocketAddress)>,
    /// Задача чтения потока.
    reader: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for AnyTlsDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsDatagram")
            .field("pool", &self.pool)
            .finish()
    }
}

impl AnyTlsDatagram {
    /// Заводит канал. Потока при этом не открывается.
    pub fn new(pool: Arc<SessionPool>) -> Self {
        let (sender, incoming) = mpsc::channel(QUEUE);
        Self {
            pool,
            outgoing: Mutex::new(None),
            incoming: Mutex::new(incoming),
            sender,
            reader: Mutex::new(None),
        }
    }

    /// Открывает поток с датаграммами и объявляет первого адресата.
    async fn open(&self, first: &SocketAddress) -> Result<WriteHalf<AnyTlsStream>, ProtocolError> {
        let mut stream = self.pool.open().await?;

        let mut header = Vec::new();
        socks::encode(&uot::magic_target(), &mut header).map_err(AnyTlsError::from)?;
        header.extend_from_slice(&uot::request(false, first)?);

        deadline::handshake::<_, AnyTlsError>("заголовок датаграмм AnyTLS", async {
            stream.write_all(&header).await?;
            stream.flush().await?;
            Ok(())
        })
        .await?;

        let (recv, send) = tokio::io::split(stream);
        let reader = tokio::spawn(read_packets(recv, self.sender.clone()));
        if let Some(previous) = self.reader.lock().await.replace(reader) {
            previous.abort();
        }
        Ok(send)
    }
}

#[async_trait]
impl ProxyDatagram for AnyTlsDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        if payload.len() > uot::MAX_PAYLOAD {
            return Err(AnyTlsError::Oversized(payload.len()).into());
        }

        let mut outgoing = self.outgoing.lock().await;
        if outgoing.is_none() {
            *outgoing = Some(self.open(target).await?);
        }
        let Some(io) = outgoing.as_mut() else {
            return Err(AnyTlsError::disconnected("поток датаграмм не открылся").into());
        };

        let mut frame = Vec::with_capacity(uot::address_len(target) + 2 + payload.len());
        uot::encode_address(target, &mut frame)?;
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(&payload);

        io.write_all(&frame).await.map_err(AnyTlsError::Io)?;
        io.flush().await.map_err(AnyTlsError::Io)?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let mut incoming = self.incoming.lock().await;
        incoming
            .recv()
            .await
            .ok_or_else(|| AnyTlsError::disconnected("поток датаграмм закрылся").into())
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        if let Some(reader) = self.reader.lock().await.take() {
            reader.abort();
        }
        self.outgoing.lock().await.take();
        Ok(())
    }
}

/// Читает датаграммы из потока, пока он жив.
async fn read_packets(
    mut io: ReadHalf<AnyTlsStream>,
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

/// Читает адрес по байту, пока разбор [`crate::uot`] не скажет «хватит».
async fn read_address(io: &mut ReadHalf<AnyTlsStream>) -> AnyTlsResult<SocketAddress> {
    let mut buffer = Vec::with_capacity(uot::MAX_ADDRESS);
    loop {
        if let Some((address, _)) = uot::decode_address(&buffer)? {
            return Ok(address);
        }
        if buffer.len() >= uot::MAX_ADDRESS {
            return Err(AnyTlsError::malformed("адрес датаграммы не кончается"));
        }
        let mut byte = [0_u8; 1];
        io.read_exact(&mut byte).await?;
        buffer.push(byte[0]);
    }
}
