//! Датаграммный канал по HTTP/2: один поток `connect-udp`, датаграммы — капсулами.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use h2::SendStream;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use tokio::sync::Mutex;

use crate::error::PingwinError;
use crate::tcp::io::{self, H2Recv};
use crate::wire::{capsule, udp};

/// Приём: поток и недоразобранный хвост.
struct Incoming {
    recv: H2Recv,
    buffer: BytesMut,
}

/// Датаграммный канал Pingwin поверх TCP.
pub struct TcpDatagram {
    /// `None` — канал закрыт.
    send: Mutex<Option<SendStream<Bytes>>>,
    incoming: Mutex<Incoming>,
}

impl std::fmt::Debug for TcpDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpDatagram").finish_non_exhaustive()
    }
}

impl TcpDatagram {
    pub(crate) fn new(send: SendStream<Bytes>, recv: H2Recv) -> Self {
        Self {
            send: Mutex::new(Some(send)),
            incoming: Mutex::new(Incoming {
                recv,
                buffer: BytesMut::new(),
            }),
        }
    }
}

fn closed() -> ProtocolError {
    PingwinError::disconnected("датаграммный канал закрылся").into()
}

#[async_trait]
impl ProxyDatagram for TcpDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let body = udp::encode(target, &payload)?;
        if body.len() > capsule::MAX_LEN {
            return Err(PingwinError::Oversized(body.len()).into());
        }
        let mut frame = Vec::with_capacity(body.len() + 8);
        capsule::encode_into(&body, &mut frame);

        let mut send = self.send.lock().await;
        let send = send.as_mut().ok_or_else(closed)?;
        io::send_all(send, Bytes::from(frame))
            .await
            .map_err(PingwinError::from)?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let mut incoming = self.incoming.lock().await;
        let Incoming { recv, buffer } = &mut *incoming;
        loop {
            while let Some(datagram) = capsule::decode(buffer)? {
                match udp::decode(datagram) {
                    Some((from, data)) => return Ok((data, from)),
                    None => tracing::trace!("датаграмма без адреса отброшена"),
                }
            }
            let chunk = recv
                .chunk()
                .await
                .map_err(PingwinError::from)?
                .ok_or_else(closed)?;
            buffer.extend_from_slice(&chunk);
        }
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        if let Some(mut send) = self.send.lock().await.take()
            && let Err(err) = send.send_data(Bytes::new(), true)
        {
            tracing::trace!(%err, "канал уже закрыт");
        }
        Ok(())
    }
}
