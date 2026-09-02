//! UDP-сокет, через который QUIC говорит с сервером.
//!
//! Обычно quinn работает со своим сокетом и пользуется всем, что даёт ядро:
//! отправкой нескольких датаграмм одним вызовом (GSO) и их приёмом пачкой
//! (GRO). Пока обфускации и смены порта нет, так и надо — этот модуль в игру
//! не вступает.
//!
//! Он нужен, когда каждый пакет надо потрогать по одному:
//!
//! - **обфускация** меняет содержимое пакета целиком, включая заголовок QUIC;
//! - **смена порта** меняет адрес назначения, о чём quinn знать не должен.
//!
//! Второе стоит пояснить. quinn считает, что у соединения один адрес
//! собеседника; пакет с другого порта он посчитал бы попыткой смены пути и
//! отбросил. Поэтому подмена делается ровно здесь и симметрично: на отправке
//! порт заменяется на текущий, на приёме — обратно на тот, который quinn
//! считает адресом сервера. Выше по стеку смены порта не видно вовсе.

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

/// Размер буфера, на котором собирается исходящий пакет.
///
/// Больше любого разумного путевого MTU. Пакет крупнее уложится в выделенный
/// буфер — это редкий путь, и платить за него аллокацией не жалко.
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

    /// Насколько обфускация удлиняет пакет.
    ///
    /// На эту величину `quic.rs` уменьшает объявленный QUIC размер датаграммы:
    /// иначе обфусцированный пакет перестанет помещаться в путевой MTU.
    pub fn overhead(&self) -> usize {
        self.obfs.as_ref().map_or(0, |o| o.overhead())
    }

    /// Куда отправлять с учётом смены порта.
    fn destination(&self, requested: SocketAddr) -> SocketAddr {
        match &self.hop {
            // Порт подменяется только у самого сервера: чужой адрес трогать
            // нельзя, даже если он сюда как-то попал.
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
        if needed <= SCRATCH {
            let mut scratch = [0u8; SCRATCH];
            let len = obfs
                .obfuscate(packet, &mut scratch)
                .ok_or_else(|| io::Error::other("обфускация не уместилась в буфер"))?;
            self.inner.try_send_to(&scratch[..len], destination)?;
        } else {
            let mut scratch = vec![0u8; needed];
            let len = obfs
                .obfuscate(packet, &mut scratch)
                .ok_or_else(|| io::Error::other("обфускация не уместилась в буфер"))?;
            self.inner.try_send_to(&scratch[..len], destination)?;
        }
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

        // `max_transmit_segments` объявлен единицей, поэтому quinn сюда пачек
        // не кладёт. Разбор всё равно есть: молча слепить несколько датаграмм
        // в одну — это порча трафика, которую потом не найти.
        let segments: Box<dyn Iterator<Item = &[u8]>> = match transmit.segment_size {
            Some(size) if size > 0 && size < transmit.contents.len() => {
                Box::new(transmit.contents.chunks(size))
            }
            _ => Box::new(std::iter::once(transmit.contents)),
        };

        for segment in segments {
            #[cfg(feature = "obfs-gecko")]
            if let Some(gecko) = &self.gecko
                && Gecko::applies_to(segment)
                && let Some(frames) = gecko.fragment(segment)
            {
                for frame in frames {
                    // Часть не ушла — остальные тоже не отправляем. Для QUIC
                    // это выглядит потерей пакета, а он к потерям готов;
                    // досылать половину бессмысленно, целого пакета всё равно
                    // не получится.
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

        // Цикл, а не один заход: пакет может оказаться мусором с открытого
        // порта или частью ещё не собранного целого. В обоих случаях отдавать
        // наверх нечего, и надо ждать следующего.
        loop {
            let mut read = ReadBuf::new(buf);
            let actual = ready!(self.inner.poll_recv_from(cx, &mut read))?;
            let mut len = read.filled().len();

            if let Some(obfs) = &self.obfs {
                match obfs.deobfuscate(&mut buf[..len]) {
                    Some(shorter) => len = shorter,
                    // На открытый UDP-порт стучится кто угодно; это фон, а не
                    // ошибка соединения.
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
        // Аппаратная сегментация несовместима с обфускацией: она склеивает
        // датаграммы в одну отправку, а обфускатор обязан видеть каждую
        // отдельно.
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

        // Обратно quinn обязан увидеть тот адрес, к которому подключался, —
        // иначе он посчитает ответ попыткой смены пути и отбросит его.
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
