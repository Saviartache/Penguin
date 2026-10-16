//! Датаграммный канал, выданный командой `UDP ASSOCIATE`.
//!
//! Датаграммы идут мимо TLS даже у `socks5-tls`: потока, к которому его привязать, нет.
//!
//! Управляющее соединение лежит в структуре: прокси держит разрешение, пока оно живо
//! (RFC 1928, §7). Отправитель сверяется по IP, не по порту: адрес из ответа
//! `UDP ASSOCIATE` — куда слать, а не откуда получать.

use std::net::SocketAddr;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::SocketAddress;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_proto::stream::ProxyStream;
use tokio::net::UdpSocket;

use crate::frame::udp;

/// Канал датаграмм через прокси.
pub struct Socks5Datagram {
    socket: UdpSocket,
    /// Адрес из ответа на `UDP ASSOCIATE`.
    relay: SocketAddr,
    /// Управляющее соединение; `Mutex` только ради `Sync` (`ProxyStream` не `Sync`).
    _control: Mutex<Box<dyn ProxyStream>>,
}

impl std::fmt::Debug for Socks5Datagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5Datagram")
            .field("relay", &self.relay)
            .finish()
    }
}

impl Socks5Datagram {
    /// Собирает канал вокруг уже открытого сокета и выданного адреса.
    pub fn new(socket: UdpSocket, relay: SocketAddr, control: Box<dyn ProxyStream>) -> Self {
        Self {
            socket,
            relay,
            _control: Mutex::new(control),
        }
    }
}

#[async_trait]
impl ProxyDatagram for Socks5Datagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let frame = udp::encode(target, &payload)?;
        self.socket.send_to(&frame, self.relay).await?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        // 65 535 — наибольшая датаграмма; обрезка испортила бы данные
        let mut buf = vec![0u8; 65_535];
        loop {
            let (len, from) = self.socket.recv_from(&mut buf).await?;
            if from.ip() != self.relay.ip() {
                tracing::debug!(%from, "датаграмма не от прокси — отброшена");
                continue;
            }

            // Дроблёная или короткая — как потерянный пакет
            if let Some((source, payload)) = udp::decode(&buf[..len])? {
                return Ok((payload, source));
            }
        }
    }
}
