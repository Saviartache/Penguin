//! UDP в режиме DPI: датаграммы уходят как есть.
//!
//! Обход сюда не переносится и не будет: он режет **поток**, а в UDP потока
//! нет — каждая датаграмма едет сама по себе, и резать её значит потерять
//! половину. Приёмы `zapret2` для UDP требуют своего заголовка, то есть сырого
//! сокета, которого у нас нет (документ [`penguin_transport::desync`]).

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::{Address, SocketAddress};
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use tokio::net::UdpSocket;

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

    /// Превращает адрес назначения в числовой.
    async fn resolve(&self, target: &SocketAddress) -> Result<SocketAddr, ProtocolError> {
        match &target.host {
            Address::Ip(ip) => Ok(SocketAddr::new(*ip, target.port)),
            Address::Domain(domain) => self
                .dialer
                .resolve(domain)
                .await?
                .into_iter()
                .next()
                .map(|ip| SocketAddr::new(ip, target.port))
                .ok_or_else(|| ProtocolError::Unreachable(domain.clone())),
        }
    }
}

#[async_trait]
impl ProxyDatagram for DirectDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let addr = self.resolve(target).await?;
        self.socket.send_to(&payload, addr).await?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        // 65 535 — наибольшая датаграмма, которую вообще можно получить.
        // Обрезать её было бы порчей данных: приложение не узнает о потере.
        let mut buf = vec![0u8; 65_535];
        let (len, from) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        Ok((Bytes::from(buf), SocketAddress::from(from)))
    }
}
