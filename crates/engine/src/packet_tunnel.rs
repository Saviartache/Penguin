//! Направление уровня пакетов, надетое на трейт [`Outbound`].
//!
//! Последнее звено моста. Ниже него — [`crate::packet::PacketDevice`] и
//! исходящий стек, выше — весь остальной движок, который про пакеты ничего не
//! знает и знать не должен.
//!
//! ```text
//!   конвейер ──► Outbound ──► PacketTunnel ──► netstack::outgoing
//!                                                    │
//!                                             PacketDevice
//!                                                    │
//!                                             PacketOutbound (WireGuard)
//! ```
//!
//! Ради этого звена ни `router`, ни `pipeline`, ни `gui` не меняются ни одной
//! строкой: для них WireGuard — такое же направление, как Trojan.
//!
//! # Имена сюда пока не доходят
//!
//! [`Outbound::connect_tcp`] обещает, что `target` может быть доменом и
//! разрешать его — дело той стороны. У пакетного тоннеля «та сторона» — это
//! сеть внутри него, и разрешать имя надо запросом DNS **через тоннель**, а не
//! снаружи: разрешить снаружи значит отдать провайдеру список имён, которые
//! человек спрашивает, — ровно то, от чего он и ставил клиент.
//!
//! Своего DNS внутри тоннеля пока нет: в [`PacketInterface`] нет поля с
//! адресом сервера имён, а завести его — значит поменять договор в
//! `penguin-proto`. Поэтому сейчас доменное имя честно отвергается с
//! объяснением, а не разрешается тайком мимо тоннеля. Разбор вопроса — в
//! `plan.md`, фаза 18.
//!
//! [`PacketInterface`]: penguin_proto::packet::PacketInterface

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use penguin_core::address::{Address, SocketAddress};
use penguin_core::id::OutboundId;
use penguin_netstack::Datagram;
use penguin_netstack::config::StackConfig;
use penguin_netstack::outgoing::{self, ConnectError, Connector};
use penguin_proto::capabilities::Capabilities;
use penguin_proto::datagram::ProxyDatagram;
use penguin_proto::error::ProtocolError;
use penguin_proto::outbound::Outbound;
use penguin_proto::packet::PacketOutbound;
use penguin_proto::stream::ProxyStream;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use crate::packet::PacketDevice;

/// Сколько датаграмм держать в очереди одной сессии.
const SESSION_QUEUE: usize = 128;

/// Кому какая сессия принадлежит.
type Sessions = Arc<DashMap<SocketAddr, mpsc::Sender<(Bytes, SocketAddr)>>>;

/// Пакетное направление, выглядящее для движка обычным.
pub struct PacketTunnel {
    outbound: Arc<dyn PacketOutbound>,
    connector: Connector,
    udp_send: mpsc::Sender<Datagram>,
    sessions: Sessions,
    /// Чем метится следующая сессия UDP.
    next_tag: AtomicU16,
    cancel: CancellationToken,
}

impl PacketTunnel {
    /// Поднимает исходящий стек поверх направления.
    ///
    /// Отмена своя, а не общая: закрытие профиля обязано останавливать стек
    /// этого направления и только его.
    pub fn new(outbound: Arc<dyn PacketOutbound>) -> Self {
        let device = PacketDevice::new(Arc::clone(&outbound));
        let config = device.stack_config();
        let cancel = CancellationToken::new();
        let handles = outgoing::spawn(Box::new(device), config, cancel.clone());

        let sessions: Sessions = Arc::new(DashMap::new());
        tokio::spawn(demultiplex(
            handles.udp_recv,
            Arc::clone(&sessions),
            cancel.clone(),
        ));

        Self {
            outbound,
            connector: handles.connector,
            udp_send: handles.udp_send,
            sessions,
            next_tag: AtomicU16::new(1),
            cancel,
        }
    }

    /// Метка, под которой стек будет узнавать сессию.
    ///
    /// Адрес выдуманный и на провод не попадает никогда: стек возит его туда и
    /// обратно нетронутым, чтобы вернуть ответ хозяину
    /// (`netstack::outgoing::nat`). Занятая метка пропускается — иначе две
    /// сессии получали бы чужие ответы.
    fn take_tag(&self) -> Option<SocketAddr> {
        for _ in 0..u16::MAX {
            let port = self.next_tag.fetch_add(1, Ordering::Relaxed);
            if port == 0 {
                continue;
            }
            let tag = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
            if !self.sessions.contains_key(&tag) {
                return Some(tag);
            }
        }
        None
    }

    /// Настройки стека, с которыми он поднят, — для журнала и тестов.
    pub fn stack_config(&self) -> StackConfig {
        PacketDevice::new(Arc::clone(&self.outbound)).stack_config()
    }
}

impl std::fmt::Debug for PacketTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketTunnel")
            .field("protocol", &self.outbound.protocol())
            .finish()
    }
}

#[async_trait]
impl Outbound for PacketTunnel {
    fn id(&self) -> OutboundId {
        self.outbound.id()
    }

    fn protocol(&self) -> &'static str {
        self.outbound.protocol()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // Датаграммы у тоннеля есть: они и так пакеты.
            udp: true,
            // Имя разрешает не та сторона, а мы сами: см. шапку модуля.
            remote_dns: false,
            // Соединения живут в одном тоннеле, и рукопожатие на каждое не
            // тратится — это и есть мультиплексирование.
            multiplex: true,
            ..Capabilities::default()
        }
    }

    async fn connect_tcp(
        &self,
        target: &SocketAddress,
    ) -> Result<Box<dyn ProxyStream>, ProtocolError> {
        let address = ip_of(target)?;
        let stream = self.connector.connect(address).await.map_err(translate)?;
        Ok(Box::new(stream))
    }

    async fn bind_udp(&self) -> Result<Box<dyn ProxyDatagram>, ProtocolError> {
        let tag = self.take_tag().ok_or(ProtocolError::Unreachable(
            "свободных сессий UDP в тоннеле не осталось".to_owned(),
        ))?;
        let (incoming, answers) = mpsc::channel(SESSION_QUEUE);
        self.sessions.insert(tag, incoming);

        Ok(Box::new(TunnelDatagram {
            tag,
            outgoing: self.udp_send.clone(),
            answers: Mutex::new(answers),
            sessions: Arc::clone(&self.sessions),
        }))
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        self.cancel.cancel();
        self.outbound.close().await
    }
}

/// Разводит ответы по сессиям.
///
/// Очередь ответов у стека одна на весь тоннель, а канал движку выдаётся на
/// каждую сессию приложения. Метка, которую стек возит нетронутой, — это и
/// есть то, по чему они различаются.
async fn demultiplex(
    mut answers: mpsc::Receiver<Datagram>,
    sessions: Sessions,
    cancel: CancellationToken,
) {
    loop {
        let datagram = tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            datagram = answers.recv() => datagram,
        };
        let Some(datagram) = datagram else { break };

        let Some(session) = sessions.get(&datagram.source) else {
            // Сессия закрылась, пока ответ шёл. Обычное дело для UDP.
            continue;
        };
        // Не блокируя: медленная сессия не должна останавливать остальные, а
        // потеря датаграммы для UDP — обычный исход.
        if session
            .try_send((datagram.payload, datagram.destination))
            .is_err()
        {
            tracing::trace!("очередь сессии UDP переполнена, ответ отброшен");
        }
    }
}

/// Датаграммный канал одной сессии приложения.
struct TunnelDatagram {
    /// Метка сессии: по ней приходит ответ.
    tag: SocketAddr,
    outgoing: mpsc::Sender<Datagram>,
    answers: Mutex<mpsc::Receiver<(Bytes, SocketAddr)>>,
    sessions: Sessions,
}

impl std::fmt::Debug for TunnelDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelDatagram")
            .field("tag", &self.tag)
            .finish()
    }
}

#[async_trait]
impl ProxyDatagram for TunnelDatagram {
    async fn send_to(&self, payload: Bytes, target: &SocketAddress) -> Result<(), ProtocolError> {
        let destination = ip_of(target)?;
        self.outgoing
            .send(Datagram {
                source: self.tag,
                destination,
                payload,
            })
            .await
            .map_err(|_| ProtocolError::Disconnected("тоннель остановлен".to_owned()))
    }

    async fn recv_from(&self) -> Result<(Bytes, SocketAddress), ProtocolError> {
        let mut answers = self.answers.lock().await;
        let (payload, from) = answers
            .recv()
            .await
            .ok_or_else(|| ProtocolError::Disconnected("тоннель остановлен".to_owned()))?;
        Ok((
            payload,
            SocketAddress::new(Address::Ip(from.ip()), from.port()),
        ))
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        // Метка обязана освободиться: иначе она занята навсегда, а сессий
        // всего шестьдесят пять тысяч.
        self.sessions.remove(&self.tag);
        Ok(())
    }
}

impl Drop for TunnelDatagram {
    /// Сессию закрывают не всегда: конвейер роняет канал по таймауту тишины.
    fn drop(&mut self) {
        self.sessions.remove(&self.tag);
    }
}

/// Адрес назначения в виде, который понимает тоннель.
///
/// Имя здесь — не поломка, а неподключённая часть: сказать об этом надо
/// текстом, который объясняет, что делать, а не «неверный адрес».
fn ip_of(target: &SocketAddress) -> Result<SocketAddr, ProtocolError> {
    match &target.host {
        Address::Ip(ip) => Ok(SocketAddr::new(*ip, target.port)),
        // Не `Unsupported`: тот несёт только постоянную строку, а имя в
        // сообщении и есть самое полезное в нём. `InvalidConfig` при этом не
        // повторяется — и правильно: следующая попытка кончится тем же.
        Address::Domain(name) => Err(ProtocolError::InvalidConfig(format!(
            "пакетный тоннель не умеет разрешать имена: `{name}` надо спросить \
             у DNS внутри тоннеля, а его пока нет"
        ))),
    }
}

/// Отказ стека на языке протокола.
///
/// Различие не косметическое: по нему `supervisor` решает, повторять ли
/// попытку. Молчание и отказ повторить стоит, отсутствие адреса — нет.
fn translate(error: ConnectError) -> ProtocolError {
    match error {
        ConnectError::Refused(address) => {
            ProtocolError::Unreachable(format!("{address} отказал в соединении"))
        }
        ConnectError::TimedOut(address) => {
            ProtocolError::Connect(format!("нет ответа от {address}"))
        }
        // Не сеть: с этим интерфейсом туда не дойти вовсе, и следующая попытка
        // кончится тем же.
        ConnectError::NoAddress(address) => ProtocolError::InvalidConfig(format!(
            "у интерфейса тоннеля нет адреса, с которого идти на {address}"
        )),
        ConnectError::NoPorts => {
            ProtocolError::Unreachable("свободных портов в тоннеле не осталось".to_owned())
        }
        ConnectError::Stopped => ProtocolError::Disconnected("тоннель остановлен".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    use bytes::Bytes;
    use penguin_proto::packet::PacketInterface;

    use super::*;

    /// Направление, которое никуда не ходит.
    struct Silent {
        sent: Mutex<Vec<Vec<u8>>>,
    }

    impl Silent {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                sent: Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait]
    impl PacketOutbound for Silent {
        fn id(&self) -> OutboundId {
            OutboundId::new("проверка")
        }

        fn protocol(&self) -> &'static str {
            "wireguard"
        }

        fn interface(&self) -> PacketInterface {
            PacketInterface {
                ipv4: (Ipv4Addr::new(10, 7, 0, 2), 24),
                ipv6: None,
                mtu: 1420,
            }
        }

        async fn send(&self, packet: &[u8]) -> Result<(), ProtocolError> {
            self.sent.lock().expect("замок").push(packet.to_vec());
            Ok(())
        }

        async fn recv(&self) -> Result<Bytes, ProtocolError> {
            // Никогда не отвечает: так выглядит сервер, до которого не дошло.
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn the_tunnel_looks_like_an_ordinary_direction() {
        // Ради этого мост и писался: для конвейера WireGuard такое же
        // направление, как Trojan.
        let tunnel = PacketTunnel::new(Silent::new());
        assert_eq!(tunnel.protocol(), "wireguard");
        assert_eq!(tunnel.id(), OutboundId::new("проверка"));

        let capabilities = tunnel.capabilities();
        assert!(capabilities.multiplex, "соединения живут в одном тоннеле");
        assert!(
            !capabilities.remote_dns,
            "имя разрешает не та сторона, а мы сами"
        );
    }

    #[tokio::test]
    async fn the_stack_gets_the_address_the_server_gave() {
        let tunnel = PacketTunnel::new(Silent::new());
        let config = tunnel.stack_config();
        assert_eq!(config.ipv4, (Ipv4Addr::new(10, 7, 0, 2), 24));
        assert_eq!(config.mtu, 1420);
    }

    #[tokio::test]
    async fn a_domain_is_refused_with_an_explanation_not_resolved_outside() {
        // Разрешить имя снаружи значило бы отдать провайдеру список имён,
        // которые человек спрашивает, — ровно то, от чего ставили клиент.
        let tunnel = PacketTunnel::new(Silent::new());
        let target: SocketAddress = "example.com:443".parse().expect("адрес");

        // `unwrap_err` здесь не годится: у `dyn ProxyStream` нет `Debug`.
        let error = tunnel
            .connect_tcp(&target)
            .await
            .err()
            .expect("имя не должно разрешаться мимо тоннеля");
        assert!(!error.is_retryable(), "повтор ничего не изменит");
        assert!(error.to_string().contains("example.com"), "{error}");
    }

    #[tokio::test]
    async fn every_udp_session_gets_its_own_tag() {
        // Одна метка на две сессии означает, что ответ придёт не тому.
        let tunnel = PacketTunnel::new(Silent::new());
        let first = tunnel.bind_udp().await.expect("канал");
        let second = tunnel.bind_udp().await.expect("канал");

        assert_eq!(tunnel.sessions.len(), 2);
        drop(first);
        drop(second);
    }

    #[tokio::test]
    async fn a_closed_session_frees_its_tag() {
        // Меток всего шестьдесят пять тысяч, и занятая навсегда — утечка.
        let tunnel = PacketTunnel::new(Silent::new());
        let channel = tunnel.bind_udp().await.expect("канал");
        assert_eq!(tunnel.sessions.len(), 1);

        channel.close().await.expect("закрылся");
        assert!(tunnel.sessions.is_empty());
    }

    #[tokio::test]
    async fn a_dropped_session_frees_its_tag_too() {
        // Конвейер роняет канал по таймауту тишины, не закрывая его.
        let tunnel = PacketTunnel::new(Silent::new());
        drop(tunnel.bind_udp().await.expect("канал"));
        assert!(tunnel.sessions.is_empty());
    }

    #[tokio::test]
    async fn a_datagram_reaches_the_direction_as_a_packet() {
        let outbound = Silent::new();
        let tunnel = PacketTunnel::new(Arc::clone(&outbound) as Arc<dyn PacketOutbound>);
        let channel = tunnel.bind_udp().await.expect("канал");

        let target: SocketAddress = "8.8.8.8:53".parse().expect("адрес");
        channel
            .send_to(Bytes::from_static(b"query"), &target)
            .await
            .expect("ушла");

        // Стеку нужен оборот цикла, чтобы собрать пакет и отдать его наружу.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let sent = outbound.sent.lock().expect("замок");
        assert!(
            sent.iter().any(|packet| packet.ends_with(b"query")),
            "датаграмма не дошла до направления"
        );
    }

    #[tokio::test]
    async fn a_domain_is_refused_on_the_datagram_side_as_well() {
        let tunnel = PacketTunnel::new(Silent::new());
        let channel = tunnel.bind_udp().await.expect("канал");
        let target: SocketAddress = "dns.example.com:53".parse().expect("адрес");

        let error = channel
            .send_to(Bytes::from_static(b"query"), &target)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("dns.example.com"), "{error}");
    }

    #[tokio::test]
    async fn packets_reach_the_direction_when_a_connection_is_attempted() {
        // Проверяется, что стек действительно поднят на этом направлении:
        // попытка соединения обязана вылиться в пакет, ушедший в тоннель.
        let outbound = Silent::new();
        let tunnel = PacketTunnel::new(Arc::clone(&outbound) as Arc<dyn PacketOutbound>);
        let target: SocketAddress = "93.184.216.34:443".parse().expect("адрес");

        // Ответа не будет никогда — ждём только первого пакета.
        let attempt = tokio::spawn(async move { tunnel.connect_tcp(&target).await });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        assert!(
            !outbound.sent.lock().expect("замок").is_empty(),
            "в тоннель не ушло ни одного пакета: стек не поднят"
        );
        attempt.abort();
    }

    #[test]
    fn silence_is_retried_and_a_wrong_interface_is_not() {
        // По этому различию `supervisor` решает, повторять ли попытку.
        let address = "93.184.216.34:443".parse().expect("адрес");

        assert!(translate(ConnectError::TimedOut(address)).is_retryable());
        assert!(translate(ConnectError::Refused(address)).is_retryable());
        assert!(!translate(ConnectError::NoAddress(address)).is_retryable());
    }
}
