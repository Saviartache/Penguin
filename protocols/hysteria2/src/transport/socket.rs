//! UDP-сокет QUIC с обфускацией и сменой порта (иначе берётся сокет quinn с GSO/GRO).
//!
//! Смена порта подменяется здесь симметрично: на отправке порт текущий, на
//! приёме обратно адрес сервера, иначе quinn сочтёт пакет сменой пути.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

use super::hop::PortHopper;
use super::obfs::Obfuscator;
#[cfg(feature = "obfs-gecko")]
use super::obfs::gecko::{Gecko, Incoming};

/// Стековый буфер исходящего пакета; крупнее — редкий путь с аллокацией.
const SCRATCH: usize = 2048;

/// Сокет с обфускацией и сменой порта.
pub struct HysteriaSocket {
    inner: Arc<UdpSocket>,
    obfs: Option<Arc<dyn Obfuscator>>,
    #[cfg(feature = "obfs-gecko")]
    gecko: Option<Gecko>,
    hop: Option<PortHopper>,
    /// Адрес, который quinn считает адресом сервера.
    server: SocketAddr,
}

impl std::fmt::Debug for HysteriaSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HysteriaSocket")
            .field("server", &self.server)
            .field("obfs", &self.obfs.is_some())
            .field("hopping", &self.hop.is_some())
            .finish()
    }
}

impl HysteriaSocket {
    /// Собирает сокет.
    pub fn new(
        inner: Arc<UdpSocket>,
        server: SocketAddr,
        obfs: Option<Arc<dyn Obfuscator>>,
        hop: Option<PortHopper>,
    ) -> Self {
        Self {
            inner,
            obfs,
            #[cfg(feature = "obfs-gecko")]
            gecko: None,
            hop,
            server,
        }
    }

    /// Включает дробление пакетов рукопожатия.
    #[cfg(feature = "obfs-gecko")]
    pub fn with_gecko(mut self) -> Self {
        self.gecko = Some(Gecko::new());
        self
    }

    /// Удлинение пакета обфускацией; на него уменьшается размер датаграммы QUIC.
    pub fn overhead(&self) -> usize {
        self.obfs.as_ref().map_or(0, |o| o.overhead())
    }

    /// Куда отправлять с учётом смены порта.
    fn destination(&self, requested: SocketAddr) -> SocketAddr {
        match &self.hop {
            Some(hop) if requested.ip() == self.server.ip() => {
                SocketAddr::new(requested.ip(), hop.current())
            }
            _ => requested,
        }
    }

    /// Каким адресом представить отправителя.
    fn source(&self, actual: SocketAddr) -> SocketAddr {
        match &self.hop {
            Some(_) if actual.ip() == self.server.ip() => self.server,
            _ => actual,
        }
    }

    /// Отправляет один готовый пакет, применив обфускацию.
    fn send_one(&self, packet: &[u8], destination: SocketAddr) -> io::Result<()> {
        let Some(obfs) = &self.obfs else {
            self.inner.try_send_to(packet, destination)?;
            return Ok(());
        };

        let needed = packet.len() + obfs.overhead();
        let mut stack = [0u8; SCRATCH];
        let mut heap;
        let scratch = if needed <= SCRATCH {
            &mut stack[..]
        } else {
            heap = vec![0u8; needed];
            &mut heap[..]
        };
        let len = obfs
            .obfuscate(packet, scratch)
            .ok_or_else(|| io::Error::other("обфускация не уместилась в буфер"))?;
        self.inner.try_send_to(&scratch[..len], destination)?;
        Ok(())
    }
}

impl AsyncUdpSocket for HysteriaSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(WritablePoller {
            socket: Arc::clone(&self.inner),
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let destination = self.destination(transmit.destination);

        // Пачек нет (`max_transmit_segments` = 1), но склейку не допускаем.
        let size = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        for segment in transmit.contents.chunks(size) {
            #[cfg(feature = "obfs-gecko")]
            if let Some(gecko) = &self.gecko
                && Gecko::applies_to(segment)
                && let Some(frames) = gecko.fragment(segment)
            {
                for frame in frames {
                    // Часть не ушла — остальные не шлём: для QUIC это потеря пакета.
                    self.send_one(&frame, destination)?;
                }
                continue;
            }

            self.send_one(segment, destination)?;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (Some(buf), Some(meta)) = (bufs.first_mut(), meta.first_mut()) else {
            return Poll::Ready(Ok(0));
        };

        // Мусор и недособранные части наверх не отдаём — ждём следующий пакет.
        loop {
            let mut read = ReadBuf::new(buf);
            let actual = ready!(self.inner.poll_recv_from(cx, &mut read))?;
            let mut len = read.filled().len();

            if let Some(obfs) = &self.obfs {
                match obfs.deobfuscate(&mut buf[..len]) {
                    Some(shorter) => len = shorter,
                    None => continue,
                }
            }

            #[cfg(feature = "obfs-gecko")]
            if let Some(gecko) = &self.gecko {
                match gecko.accept(actual, &buf[..len]) {
                    Incoming::Passthrough => {}
                    Incoming::Complete(packet) => {
                        if packet.len() > buf.len() {
                            continue;
                        }
                        buf[..packet.len()].copy_from_slice(&packet);
                        len = packet.len();
                    }
                    Incoming::Pending | Incoming::Malformed => continue,
                }
            }

            *meta = RecvMeta {
                addr: self.source(actual),
                len,
                stride: len,
                ecn: None,
                dst_ip: None,
            };
            return Poll::Ready(Ok(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        // GSO несовместима с обфускацией: нужна каждая датаграмма отдельно.
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

/// Ожидание готовности сокета к записи.
#[derive(Debug)]
struct WritablePoller {
    socket: Arc<UdpSocket>,
}

impl UdpPoller for WritablePoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use penguin_core::endpoint::PortSpec;

    use super::*;
    use crate::transport::obfs::salamander::Salamander;

    fn socket_with(hop: Option<PortHopper>, obfs: Option<Arc<dyn Obfuscator>>) -> HysteriaSocket {
        let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("сокет");
        std_socket.set_nonblocking(true).expect("неблокирующий");
        let inner = Arc::new(UdpSocket::from_std(std_socket).expect("tokio"));
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 443);
        HysteriaSocket::new(inner, server, obfs, hop)
    }

    #[tokio::test]
    async fn without_hopping_addresses_pass_through() {
        let socket = socket_with(None, None);
        let target = "203.0.113.5:443".parse().expect("адрес");
        assert_eq!(socket.destination(target), target);
        assert_eq!(socket.source(target), target);
    }

    #[tokio::test]
    async fn hopping_rewrites_port_symmetrically() {
        let ports: PortSpec = "20000-30000".parse().expect("порты");
        let hop = PortHopper::new(ports, Duration::from_secs(30)).expect("диапазон");
        let socket = socket_with(Some(hop), None);

        let requested: SocketAddr = "203.0.113.5:443".parse().expect("адрес");
        let sent_to = socket.destination(requested);
        assert_eq!(sent_to.ip(), requested.ip());
        assert!((20000..=30000).contains(&sent_to.port()));

        assert_eq!(socket.source(sent_to), requested);
    }

    #[tokio::test]
    async fn hopping_leaves_foreign_addresses_alone() {
        let ports: PortSpec = "20000-30000".parse().expect("порты");
        let hop = PortHopper::new(ports, Duration::from_secs(30)).expect("диапазон");
        let socket = socket_with(Some(hop), None);

        let stranger: SocketAddr = "198.51.100.7:1234".parse().expect("адрес");
        assert_eq!(socket.destination(stranger), stranger);
        assert_eq!(socket.source(stranger), stranger);
    }

    #[tokio::test]
    async fn overhead_reflects_obfuscation() {
        assert_eq!(socket_with(None, None).overhead(), 0);
        let obfs: Arc<dyn Obfuscator> = Arc::new(Salamander::new("key"));
        assert_eq!(socket_with(None, Some(obfs)).overhead(), 8);
    }

    #[tokio::test]
    async fn debug_does_not_leak_the_obfuscation_key() {
        let obfs: Arc<dyn Obfuscator> = Arc::new(Salamander::new("очень секретный ключ"));
        let rendered = format!("{:?}", socket_with(None, Some(obfs)));
        assert!(
            !rendered.contains("секретный"),
            "ключ обфускации в Debug: {rendered}"
        );
    }
}
