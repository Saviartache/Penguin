//! `WireguardOutbound`: `PacketOutbound` поверх UDP-сокета от `Dialer`.
//! `send`/`recv` передают байты каналами в задачу-водитель (`driver`), которая
//! владеет сокетом и сеансом. Рукопожатие завершается до возврата из
//! [`WireguardOutbound::connect`].

mod driver;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use penguin_core::address::Address;
use penguin_core::id::OutboundId;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::packet::{PacketInterface, PacketOutbound};
use penguin_transport::deadline;
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::config::WireguardConfig;
use crate::crypto::constants::REKEY_ATTEMPT_TIME;
use crate::crypto::handshake::StaticKeys;
use crate::error::{WireguardError, WireguardResult};

/// Глубина каналов `send`/`recv`: ограничена, чтобы без читателя память не росла.
const CHANNEL_CAPACITY: usize = 256;

/// Направление WireGuard уровня пакетов.
pub struct WireguardOutbound {
    id: OutboundId,
    interface: PacketInterface,
    outbound_tx: mpsc::Sender<Bytes>,
    inbound_rx: Mutex<mpsc::Receiver<Bytes>>,
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
    driver: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl WireguardOutbound {
    /// Разрешает адрес, открывает сокет, проводит рукопожатие (срок [`REKEY_ATTEMPT_TIME`]).
    pub async fn connect(
        id: OutboundId,
        config: WireguardConfig,
        dialer: Arc<dyn Dialer>,
    ) -> WireguardResult<Self> {
        let server_addr = resolve_server(&config, dialer.as_ref()).await?;
        let local_addr = match server_addr.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = dialer
            .bind_udp(local_addr)
            .await
            .map_err(|e| WireguardError::disconnected(e.to_string()))?;
        socket.connect(server_addr).await?;
        let socket = Arc::new(socket);

        let static_keys = Arc::new(StaticKeys::new(
            config.private_key_bytes()?,
            config.server_public_key_bytes()?,
            config.preshared_key_bytes()?,
        ));
        let reserved = config.reserved;

        let session = deadline::within(
            REKEY_ATTEMPT_TIME,
            "рукопожатие WireGuard",
            driver::initial_handshake(&socket, &static_keys, reserved),
        )
        .await?;

        let interface = PacketInterface {
            ipv4: config.address_ipv4_parsed()?,
            ipv6: config.address_ipv6_parsed()?,
            mtu: config.mtu,
            dns: config.dns.clone(),
        };

        let (outbound_tx, outbound_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (inbound_tx, inbound_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let keepalive = (config.keepalive_secs > 0)
            .then(|| Duration::from_secs(u64::from(config.keepalive_secs)));

        let handle = tokio::spawn(driver::run(driver::Handles {
            socket,
            static_keys,
            reserved,
            keepalive,
            session,
            outbound_rx,
            inbound_tx,
            shutdown_rx,
        }));

        Ok(Self {
            id,
            interface,
            outbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
            driver: Mutex::new(Some(handle)),
        })
    }
}

/// Разрешает адрес сервера, если он задан доменом.
async fn resolve_server(
    config: &WireguardConfig,
    dialer: &dyn Dialer,
) -> WireguardResult<SocketAddr> {
    let port = config.server.port;
    match &config.server.host {
        Address::Ip(ip) => Ok(SocketAddr::new(*ip, port)),
        Address::Domain(domain) => {
            let addresses = dialer
                .resolve(domain)
                .await
                .map_err(|e| WireguardError::disconnected(format!("{domain}: {e}")))?;
            addresses
                .into_iter()
                .next()
                .map(|ip| SocketAddr::new(ip, port))
                .ok_or_else(|| {
                    WireguardError::disconnected(format!("{domain}: адрес не разрешился"))
                })
        }
    }
}

#[async_trait]
impl PacketOutbound for WireguardOutbound {
    fn id(&self) -> OutboundId {
        self.id.clone()
    }

    fn protocol(&self) -> &'static str {
        crate::PROTOCOL
    }

    fn interface(&self) -> PacketInterface {
        self.interface.clone()
    }

    async fn send(&self, packet: &[u8]) -> Result<(), ProtocolError> {
        if packet.len() > usize::from(self.interface.mtu) {
            return Err(WireguardError::malformed(format!(
                "пакет длиной {} байт больше MTU в {}",
                packet.len(),
                self.interface.mtu
            ))
            .into());
        }
        self.outbound_tx
            .send(Bytes::copy_from_slice(packet))
            .await
            .map_err(|_| WireguardError::Closed.into())
    }

    async fn recv(&self) -> Result<Bytes, ProtocolError> {
        let mut rx = self.inbound_rx.lock().await;
        rx.recv().await.ok_or_else(|| WireguardError::Closed.into())
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        if let Some(tx) = self.shutdown_tx.lock().await.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.driver.lock().await.take() {
            let _ = handle.await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_packet_longer_than_the_mtu_names_both_numbers_in_the_error() {
        let mtu: u16 = 1420;
        let packet_len = 1500usize;
        let err =
            WireguardError::malformed(format!("пакет длиной {packet_len} байт больше MTU в {mtu}"));
        let text = err.to_string();
        assert!(text.contains("1500"), "{text}");
        assert!(text.contains("1420"), "{text}");
    }
}
