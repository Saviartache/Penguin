//! Датаграммный канал: один запрос `connect-udp` на сессию, адрес на каждой посылке.

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
    /// Буфер кадра, общий для всех отправок.
    scratch: std::sync::Mutex<Vec<u8>>,
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
            scratch: std::sync::Mutex::default(),
        }
    }
}

#[async_trait]
impl ProxyDatagram for PingwinDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let mut body = self.scratch.lock().unwrap_or_else(|e| e.into_inner());
        udp::encode_into(target, &payload, &mut body)?;
        self.h3
            .send_datagram(self.stream_id, &body)
            .map_err(|err| match err {
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
