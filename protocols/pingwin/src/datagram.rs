//! Датаграммный канал: один запрос `connect-udp`, адрес на каждой посылке.
//!
//! Один канал обслуживает всю UDP-сессию приложения: отдельного запроса на
//! каждого собеседника нет. Потерять датаграмму законно — это UDP; очередь
//! входящих не ждёт читателя, а выбрасывает лишнее (`penguin_transport::h3`).

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_transport::h3::{self, DatagramReceiver, H3Error, RequestStream};
use tokio::sync::Mutex;

use crate::error::PingwinError;
use crate::wire::udp;

/// Датаграммный канал Pingwin.
pub struct PingwinDatagram {
    h3: h3::Connection,
    stream_id: u64,
    /// Поток запроса держит канал открытым; `None` — закрыт.
    stream: Mutex<Option<RequestStream>>,
    incoming: Mutex<DatagramReceiver>,
}

impl std::fmt::Debug for PingwinDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PingwinDatagram")
            .field("stream_id", &self.stream_id)
            .finish()
    }
}

impl PingwinDatagram {
    pub(crate) fn new(
        h3: h3::Connection,
        stream: RequestStream,
        incoming: DatagramReceiver,
    ) -> Self {
        Self {
            h3,
            stream_id: stream.id(),
            stream: Mutex::new(Some(stream)),
            incoming: Mutex::new(incoming),
        }
    }
}

#[async_trait]
impl ProxyDatagram for PingwinDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let body = udp::encode(target, &payload)?;
        self.h3
            .send_datagram(self.stream_id, &body)
            .map_err(|err| match err {
                // Резать датаграмму нельзя: границы посылки — это и есть UDP.
                H3Error::DatagramTooLarge => PingwinError::Oversized(body.len()),
                err => err.into(),
            })?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let mut incoming = self.incoming.lock().await;
        loop {
            let datagram = incoming.recv().await.ok_or_else(|| {
                ProtocolError::from(PingwinError::disconnected("датаграммный канал закрылся"))
            })?;
            match udp::decode(datagram) {
                Some((from, data)) => return Ok((data, from)),
                None => tracing::trace!("датаграмма без адреса отброшена"),
            }
        }
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        if let Some(mut stream) = self.stream.lock().await.take()
            && let Err(err) = stream.finish()
        {
            tracing::trace!(%err, "канал уже закрыт");
        }
        Ok(())
    }
}
