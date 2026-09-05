//! Канал датаграмм: один сокет UDP, своя соль на каждой посылке.
//!
//! Устроен так же, как у Shadowsocks (`protocols/shadowsocks/src/datagram.rs`):
//! один сокет на весь канал, сервер называется числовым адресом заранее, а
//! адрес назначения едет вместе с каждой датаграммой внутри шифра. Отличается
//! только сам кадр — метка времени в запросе и её проверка на сервере
//! (`crate::frame::udp`).

use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use tokio::net::UdpSocket;

use crate::frame::clock::now_unix;
use crate::frame::udp::{self, MAX_DATAGRAM};

/// Канал датаграмм через сервер Brook.
pub struct BrookDatagram {
    socket: UdpSocket,
    server: SocketAddr,
    password: Vec<u8>,
}

impl std::fmt::Debug for BrookDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrookDatagram")
            .field("server", &self.server)
            .finish()
    }
}

impl BrookDatagram {
    /// Собирает канал вокруг уже открытого сокета.
    pub fn new(socket: UdpSocket, server: SocketAddr, password: Vec<u8>) -> Self {
        Self {
            socket,
            server,
            password,
        }
    }
}

#[async_trait]
impl ProxyDatagram for BrookDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let now = now_unix();
        let frame = udp::seal_client_datagram(&self.password, now, target, &payload)
            .map_err(ProtocolError::from)?;
        self.socket.send_to(&frame, self.server).await?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        loop {
            let mut buffer = vec![0u8; MAX_DATAGRAM];
            let (len, from) = self.socket.recv_from(&mut buffer).await?;

            // Чужая датаграмма — это фон открытого порта, а не ошибка канала.
            if from.ip() != self.server.ip() {
                tracing::debug!(%from, "датаграмма не от сервера — отброшена");
                continue;
            }
            buffer.truncate(len);

            match udp::open_server_datagram(&self.password, &mut buffer) {
                Ok((address, range)) => {
                    let payload = Bytes::copy_from_slice(&buffer[range]);
                    return Ok((payload, address));
                }
                // Не расшифровалась — почти всегда чужой пакет на наш порт,
                // а не повод рвать канал: для UDP это то же самое, что
                // потерянный пакет.
                Err(err) => {
                    tracing::debug!(%from, %err, "датаграмма не разобралась — отброшена");
                    continue;
                }
            }
        }
    }
}
