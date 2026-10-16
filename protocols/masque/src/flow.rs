//! Один канал `CONNECT-UDP`: поток HTTP/3 до одного адреса назначения.
//!
//! Отправка: кадр `HTTP/3 DATAGRAM`, если обе стороны объявили
//! `SETTINGS_H3_DATAGRAM` ([`h3::Connection::datagrams_available`]); иначе и
//! для пакета, не влезающего в датаграмму QUIC, — капсула `DATAGRAM` в потоке
//! (RFC 9297, §3.5). Приём — оба способа.

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
    /// Заводит канал вокруг подтверждённого потока и запускает приём;
    /// `incoming` — общая очередь [`crate::datagram::MasqueDatagram`].
    pub fn new(
        target: SocketAddress,
        stream: RequestStream,
        h3: h3::Connection,
        incoming: mpsc::Sender<(Bytes, SocketAddress)>,
    ) -> Self {
        let stream_id = stream.id();
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

    /// Отправляет UDP-нагрузку датаграммой HTTP/3, иначе капсулой.
    pub async fn send(&self, payload: &[u8]) -> MasqueResult<()> {
        if self.h3.datagrams_available() {
            let datagram = capsule::encode_udp_payload(payload)?;
            match self.h3.send_datagram(self.stream_id, &datagram) {
                Ok(()) => return Ok(()),
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
        self.reader.abort();
    }
}

/// Принимает капсулы и датаграммы HTTP/3 канала в общую очередь; кончается
/// вместе с потоком.
async fn receive(
    mut recv: RecvStream,
    mut datagrams: Option<DatagramReceiver>,
    target: SocketAddress,
    incoming: mpsc::Sender<(Bytes, SocketAddress)>,
) {
    let mut reader = CapsuleReader::new();
    let mut chunk = vec![0u8; READ_CHUNK];

    loop {
        tokio::select! {
            read = recv.read(&mut chunk) => match read {
                Ok(0) => return,
                Ok(n) => {
                    reader.push(&chunk[..n]);
                    if !forward_capsules(&mut reader, &target, &incoming).await {
                        return;
                    }
                }
                Err(err) => {
                    tracing::debug!(%target, %err, "канал CONNECT-UDP оборвался при чтении");
                    return;
                }
            },
            Some(datagram) = next_datagram(&mut datagrams) => {
                match capsule::decode_udp_payload(datagram) {
                    Ok(Some(payload)) => {
                        if incoming.send((payload, target.clone())).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        tracing::debug!(%target, %err, "датаграмма CONNECT-UDP не разобралась");
                    }
                }
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

/// Отдаёт собранные нагрузки в очередь; `false` — приём надо прекратить
/// (капсула испорчена, границы потеряны, либо получателя нет).
async fn forward_capsules(
    reader: &mut CapsuleReader,
    target: &SocketAddress,
    incoming: &mpsc::Sender<(Bytes, SocketAddress)>,
) -> bool {
    loop {
        match reader.next_datagram() {
            Ok(Some(payload)) => {
                if incoming.send((payload, target.clone())).await.is_err() {
                    return false;
                }
            }
            Ok(None) => return true,
            Err(err) => {
                tracing::warn!(%target, %err, "капсула CONNECT-UDP не разобралась");
                return false;
            }
        }
    }
}
