//! UDP в режиме DPI: датаграммы уходят как есть. Обход режет поток, в UDP потока нет.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use tokio::net::UdpSocket;

use crate::outbound::resolve;

/// Датаграммный канал прямо наружу.
pub struct DirectDatagram {
    socket: UdpSocket,
    dialer: Arc<dyn Dialer>,
}

impl DirectDatagram {
    /// Заводит канал поверх выданного сокета.
    pub fn new(socket: UdpSocket, dialer: Arc<dyn Dialer>) -> Self {
        Self { socket, dialer }
    }
}

#[async_trait]
impl ProxyDatagram for DirectDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let addr: SocketAddr = resolve(&*self.dialer, target).await?;
        self.socket.send_to(&payload, addr).await?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        // 65 535 — наибольшая датаграмма; обрезка испортила бы данные
        let mut buf = vec![0u8; 65_535];
        let (len, from) = self.socket.recv_from(&mut buf).await?;
        Ok((
            Bytes::copy_from_slice(&buf[..len]),
            SocketAddress::from(from),
        ))
    }
}
