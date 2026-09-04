//! Канал датаграмм: один поток на всех адресатов.
//!
//! # Почему потоком, а не датаграммой QUIC
//!
//! Ровно ради этого Juicity и написан. У TUIC датаграммы едут либо
//! датаграммами QUIC — и тогда потерянный пакет виден приложению как молчание
//! на несколько секунд, потому что повторяет уже оно само, — либо каждая
//! своим односторонним потоком, и тогда на каждый запрос DNS заводится
//! отдельный поток. Juicity возит их одним потоком с надёжной доставкой:
//! доставка тут лишняя, но она дешевле обоих способов.
//!
//! ```text
//!  заголовок потока   [3][адрес первого адресата]
//!  каждая датаграмма  [адрес][длина][данные]
//! ```
//!
//! Поток заводится **первой посылкой**, а не при создании канала: в заголовке
//! сервер ждёт адрес, и до первой посылки его неоткуда взять.

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

/// Сколько датаграмм держать в очереди, пока их не забрали.
const QUEUE: usize = 512;

/// Канал датаграмм через сервер Juicity.
pub struct JuicityDatagram {
    pool: Arc<LinkPool>,
    /// Пишущая половина потока. Пусто — посылок ещё не было.
    outgoing: Mutex<Option<Outgoing>>,
    /// Что пришло.
    incoming: Mutex<mpsc::Receiver<(Bytes, SocketAddress)>>,
    /// Его отдают задаче чтения.
    sender: mpsc::Sender<(Bytes, SocketAddress)>,
    /// Задача чтения потока.
    reader: Mutex<Option<JoinHandle<()>>>,
}

/// Пишущая сторона вместе с соединением, которое её держит.
struct Outgoing {
    /// Соединение: пока живо оно, жив и эндпойнт под потоком.
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
            // Конец потока объявляется явно: поток, который просто перестали
            // писать, для сервера выглядит живым, и его отображение адресов
            // держится до срока преобразования.
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

/// Читает адрес датаграммы.
///
/// Байт за байтом, пока разбор не скажет «хватит». Разбор при этом один и тот
/// же — тот, что проверен тестами в [`penguin_transport::addr::socks`]; своя
/// асинхронная копия ветвлений по типу адреса рано или поздно разошлась бы с
/// ним. Чтение идёт из буфера, а не из сети, поэтому байт за байтом стоит
/// столько же, сколько разом.
async fn read_address(io: &mut BufReader<quinn::RecvStream>) -> JuicityResult<SocketAddress> {
    let mut buffer = Vec::with_capacity(udp::MAX_ADDRESS);
    loop {
        if let Some((address, _)) = socks::decode(&buffer)? {
            return Ok(address);
        }
        if buffer.len() >= udp::MAX_ADDRESS {
            return Err(JuicityError::malformed("адрес датаграммы не кончается"));
        }
        let mut byte = [0_u8; 1];
        io.read_exact(&mut byte).await?;
        buffer.push(byte[0]);
    }
}
