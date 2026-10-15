//! Один канал `CONNECT-UDP`: поток HTTP/3 до одного адреса назначения.
//!
//! # Датаграммы или капсулы
//!
//! RFC 9298 переносит UDP по каналу двумя способами, и RFC 9297, §3.5
//! объявляет их семантически одинаковыми:
//!
//! - **кадром `HTTP/3 DATAGRAM`** поверх QUIC — без гарантий доставки и
//!   порядка и без задержки на потерянном пакете; ровно то, что нужно UDP;
//! - **капсулой `DATAGRAM`** в теле потока — надёжно и по порядку, ценой
//!   задержки: поток стоит, пока не пришёл потерянный кусок.
//!
//! Датаграммы — когда обе стороны объявили `SETTINGS_H3_DATAGRAM` и QUIC их
//! пропускает ([`h3::Connection::datagrams_available`]). Иначе, и для
//! пакета, не влезающего в датаграмму QUIC, — капсулы. Принимаются оба
//! способа всегда: сервер выбирает свой сам.

use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_transport::h3::{
    self, DatagramReceiver, H3Error, RecvStream, RequestStream, SendStream,
};
use tokio::io::AsyncReadExt;
use tokio::sync::{Mutex, mpsc};

use crate::capsule::{self, CapsuleReader};
use crate::error::{MasqueError, MasqueResult};

/// Размер одного чтения из потока канала.
const READ_CHUNK: usize = 16 * 1024;

/// Один канал `CONNECT-UDP` до одного адреса назначения.
pub struct Flow {
    target: SocketAddress,
    stream_id: u64,
    h3: h3::Connection,
    send: Mutex<SendStream>,
    reader: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flow")
            .field("target", &self.target)
            .field("stream_id", &self.stream_id)
            .finish()
    }
}

impl Flow {
    /// Заводит канал вокруг уже открытого и подтверждённого потока
    /// `CONNECT-UDP` и запускает приём.
    ///
    /// `incoming` — общая очередь той [`crate::datagram::MasqueDatagram`],
    /// что открыла этот канал: датаграммы от разных целей одного и того же
    /// направления `bind_udp` сходятся в одну очередь, как и у остальных
    /// протоколов с [`penguin_proto::datagram::ProxyDatagram`].
    pub fn new(
        target: SocketAddress,
        stream: RequestStream,
        h3: h3::Connection,
        incoming: mpsc::Sender<(Bytes, SocketAddress)>,
    ) -> Self {
        let stream_id = stream.id();
        // Без включённых датаграмм очереди нет — остаются капсулы.
        let datagrams = h3.register_datagrams(stream_id).ok();
        let (send, recv) = stream.split();
        let reader = tokio::spawn(receive(recv, datagrams, target.clone(), incoming));

        Self {
            target,
            stream_id,
            h3,
            send: Mutex::new(send),
            reader,
        }
    }

    /// Отправляет UDP-нагрузку: датаграммой HTTP/3, если можно, иначе
    /// капсулой `DATAGRAM` по потоку.
    pub async fn send(&self, payload: &[u8]) -> MasqueResult<()> {
        if self.h3.datagrams_available() {
            let datagram = capsule::encode_udp_payload(payload)?;
            match self.h3.send_datagram(self.stream_id, &datagram) {
                Ok(()) => return Ok(()),
                // Не влезло в датаграмму QUIC — уйдёт капсулой.
                Err(H3Error::DatagramTooLarge) => {}
                Err(err) => return Err(MasqueError::Disconnected(err.to_string())),
            }
        }
        let capsule = capsule::encode_udp_datagram(payload)?;
        self.send
            .lock()
            .await
            .send_data(&capsule)
            .await
            .map_err(|e| MasqueError::Disconnected(e.to_string()))
    }
}

impl Drop for Flow {
    fn drop(&mut self) {
        // Без этого задача приёма переживает канал и держит его половину
        // потока открытой — тот самый «после отключения не остаётся живой
        // задачи» из общего чек-листа приёмки протокола.
        self.reader.abort();
    }
}

/// Принимает UDP канала — и капсулы из потока, и датаграммы HTTP/3 — и
/// раскладывает его в общую очередь.
///
/// Останавливается сама, когда поток заканчивается или рвётся: сервер
/// закрыл канал, и открывать его снова придётся заново через
/// [`crate::session::Session::open_flow`].
async fn receive(
    mut recv: RecvStream,
    mut datagrams: Option<DatagramReceiver>,
    target: SocketAddress,
    incoming: mpsc::Sender<(Bytes, SocketAddress)>,
) {
    let mut reader = CapsuleReader::new();
    let mut chunk = vec![0u8; READ_CHUNK];

    loop {
        let payloads = tokio::select! {
            read = recv.read(&mut chunk) => match read {
                // Поток закрылся штатно — прокси завершил канал.
                Ok(0) => return,
                Ok(n) => {
                    reader.push(&chunk[..n]);
                    drain_capsules(&mut reader, &target)
                }
                Err(err) => {
                    tracing::debug!(%target, %err, "канал CONNECT-UDP оборвался при чтении");
                    return;
                }
            },
            Some(datagram) = next_datagram(&mut datagrams) => {
                match capsule::decode_udp_payload(datagram) {
                    Ok(payload) => Some(payload.into_iter().collect()),
                    Err(err) => {
                        // Одна испорченная датаграмма — потеря пакета, не обрыв.
                        tracing::debug!(%target, %err, "датаграмма CONNECT-UDP не разобралась");
                        Some(Vec::new())
                    }
                }
            }
        };
        let Some(payloads) = payloads else {
            return;
        };
        for payload in payloads {
            if incoming.send((payload, target.clone())).await.is_err() {
                // Получатель (MasqueDatagram) уже уронен — принимать некому.
                return;
            }
        }
    }
}

/// Следующая датаграмма HTTP/3; без очереди — никогда.
async fn next_datagram(datagrams: &mut Option<DatagramReceiver>) -> Option<Bytes> {
    match datagrams {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

/// Все целиком собранные нагрузки. `None` — капсула испорчена, и канал
/// дальше читать нельзя: границы следующих капсул потеряны.
fn drain_capsules(reader: &mut CapsuleReader, target: &SocketAddress) -> Option<Vec<Bytes>> {
    let mut payloads = Vec::new();
    loop {
        match reader.next_datagram() {
            Ok(Some(payload)) => payloads.push(payload),
            Ok(None) => return Some(payloads),
            Err(err) => {
                tracing::warn!(%target, %err, "капсула CONNECT-UDP не разобралась");
                return None;
            }
        }
    }
}
