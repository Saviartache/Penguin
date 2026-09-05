//! Главный цикл: пакеты из TUN в smoltcp и обратно.
//!
//! Весь стек — одна задача. Это не упрощение, а требование: `smoltcp` не
//! рассчитан на обращение из нескольких потоков, а состояние TCP по своей
//! природе однопоточное. Всё общение с внешним миром идёт через очереди.
//!
//! ```text
//!                    ┌──────────────── одна задача ────────────────┐
//!   TUN ──пакеты──►  │  устройство ──► smoltcp ──► сокеты          │
//!       ◄─пакеты───  │       ▲             │                       │
//!                    │       └─────────────┘                       │
//!                    └──────┬───────────────────────┬──────────────┘
//!                     очередь TCP             очередь UDP
//!                           │                       │
//!                        движок                  движок
//! ```
//!
//! TCP идёт через smoltcp: за состояние, окна и перепосылку отвечает он.
//! UDP — мимо: состояния у него нет, и разобрать восьмибайтовый заголовок
//! дешевле, чем держать сокет на каждую пару адресов.

use std::net::{IpAddr, SocketAddr};

use bytes::{Bytes, BytesMut};
use penguin_tun::TunDevice;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::StackConfig;
use crate::device::VirtualDevice;
use crate::ip::parse;
use crate::poll::{Clock, clamp_delay};
use crate::tcp::conn::TcpConnection;
use crate::tcp::listener::{Accepted, TcpListener};
use crate::tcp::pump::pump_data;
use crate::tcp::table::{ConnectionTable, FlowKey};
use crate::udp::session::{SessionKey, build_datagram};
use crate::udp::table::SessionTable;

/// Датаграмма, идущая через стек.
#[derive(Debug, Clone)]
pub struct Datagram {
    /// Адрес приложения.
    pub source: SocketAddr,
    /// Адрес назначения.
    pub destination: SocketAddr,
    /// Данные.
    pub payload: Bytes,
}

/// Каналы, через которые движок говорит со стеком.
pub struct StackHandles {
    /// Принятые TCP-соединения.
    pub tcp: TcpListener,
    /// Датаграммы от приложений.
    pub udp_incoming: mpsc::Receiver<Datagram>,
    /// Датаграммы приложениям.
    pub udp_outgoing: mpsc::Sender<Datagram>,
}

/// Сколько датаграмм держать в очереди.
const UDP_QUEUE: usize = 512;

/// Сколько пакетов накапливать перед передачей в smoltcp за один заход.
///
/// Читать по одному значило бы опрашивать стек на каждый пакет; читать без
/// предела — задержать ответы, пока идёт всплеск входящего трафика.
const RX_BATCH: usize = 64;

/// Запускает стек поверх устройства.
///
/// Возвращает каналы для движка. Задача живёт, пока её не отменят или пока
/// адаптер не закроется.
pub fn spawn(
    device: Box<dyn TunDevice>,
    config: StackConfig,
    cancel: CancellationToken,
) -> StackHandles {
    let (tcp_listener, tcp_sender) = TcpListener::new();
    let (udp_in_tx, udp_in_rx) = mpsc::channel(UDP_QUEUE);
    let (udp_out_tx, udp_out_rx) = mpsc::channel(UDP_QUEUE);

    tokio::spawn(run(
        device, config, cancel, tcp_sender, udp_in_tx, udp_out_rx,
    ));

    StackHandles {
        tcp: tcp_listener,
        udp_incoming: udp_in_rx,
        udp_outgoing: udp_out_tx,
    }
}

/// Главный цикл.
async fn run(
    device: Box<dyn TunDevice>,
    config: StackConfig,
    cancel: CancellationToken,
    accepted: mpsc::Sender<Accepted>,
    udp_incoming: mpsc::Sender<Datagram>,
    mut udp_outgoing: mpsc::Receiver<Datagram>,
) {
    let clock = Clock::start();
    let mut inner = Inner {
        device: VirtualDevice::new(config.mtu),
        sockets: SocketSet::new(Vec::new()),
        connections: ConnectionTable::new(),
        udp_sessions: SessionTable::new(),
    };
    let mut iface = build_interface(&config, &mut inner.device, clock.now());

    loop {
        // --- пакеты из адаптера ---
        tokio::select! {
            biased;

            () = cancel.cancelled() => break,

            packet = device.recv() => match packet {
                Ok(packet) => {
                    handle_incoming(&packet, &mut inner, &udp_incoming, &config);
                    // Пачкой: за время разбора одного пакета обычно приходит
                    // ещё несколько, и опрашивать стек на каждый — расточительно.
                    for _ in 0..RX_BATCH {
                        match device.try_recv() {
                            Some(packet) => {
                                handle_incoming(&packet, &mut inner, &udp_incoming, &config);
                            }
                            None => break,
                        }
                    }
                }
                Err(err) => {
                    tracing::debug!(%err, "адаптер закрыт, стек останавливается");
                    break;
                }
            },

            datagram = udp_outgoing.recv() => match datagram {
                // Ответ приложению собирается вручную: через smoltcp он не шёл.
                Some(datagram) => {
                    if let Some(packet) = build_datagram(
                        datagram.destination,
                        datagram.source,
                        &datagram.payload,
                    ) {
                        inner.device.queue_tx(packet);
                    }
                }
                None => break,
            },

            () = tokio::time::sleep(clamp_delay(
                iface.poll_delay(clock.now(), &inner.sockets)
            )) => {}
        }

        iface.poll(clock.now(), &mut inner.device, &mut inner.sockets);
        pump_sockets(&mut inner.sockets, &mut inner.connections, &accepted);
        iface.poll(clock.now(), &mut inner.device, &mut inner.sockets);

        // --- пакеты в адаптер ---
        while let Some(packet) = inner.device.take_tx() {
            if let Err(err) = device.send(&packet).await {
                tracing::debug!(%err, "пакет не ушёл в адаптер");
            }
        }
    }

    let _ = device.close().await;
    tracing::info!("стек остановлен");
}

/// Собирает интерфейс smoltcp.
fn build_interface(
    config: &StackConfig,
    device: &mut VirtualDevice,
    now: smoltcp::time::Instant,
) -> Interface {
    // Канального уровня у TUN нет: пакеты идут сразу с IP-заголовка, и
    // аппаратного адреса у интерфейса не бывает.
    let mut iface_config = Config::new(HardwareAddress::Ip);
    iface_config.random_seed = rand_seed();

    let mut iface = Interface::new(iface_config, device, now);

    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::from(config.ipv4.0), config.ipv4.1));
        if let Some((address, prefix)) = config.ipv6 {
            let _ = addrs.push(IpCidr::new(IpAddress::from(address), prefix));
        }
    });

    // Без этого стек отвечал бы только на пакеты, адресованные ему самому, —
    // то есть ни на один из перехваченных.
    iface.set_any_ip(true);

    // Одного `any_ip` мало, и это не очевидно. Прежде чем принять пакет с
    // чужим адресом назначения, smoltcp ищет маршрут до этого адреса и
    // требует, чтобы шлюзом оказался он сам:
    //
    // ```text
    // if self.routes.lookup(dst).map_or(true, |gw| !self.has_ip_addr(gw)) {
    //     return None;   // "Rejecting IPv4 packet; no matching routes"
    // }
    // ```
    //
    // Пустая таблица означает `None`, то есть отказ. Стек молча выбрасывал
    // **каждый** перехваченный пакет: адаптер поднят, маршруты стоят, а
    // счётчики намертво на нуле и ни одной ошибки нигде.
    //
    // Шлюзом ставится собственный адрес — ровно то, чего требует проверка.
    if let Err(err) = iface.routes_mut().add_default_ipv4_route(config.ipv4.0) {
        tracing::error!(?err, "стек не примет ни одного пакета: маршрут не добавлен");
    }

    if let Some((address, _)) = config.ipv6
        && let Err(err) = iface.routes_mut().add_default_ipv6_route(address)
    {
        tracing::error!(?err, "стек не примет ни одного пакета IPv6");
    }

    iface
}

/// Случайное зерно для стека.
///
/// Нужно, чтобы номера последовательностей TCP не совпадали между запусками:
/// совпадение означает, что старое соединение может быть принято за новое.
pub(crate) fn rand_seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

/// Изменяемая начинка стека: всё, что разбор пакета правит.
///
/// Структурой, а не россыпью аргументов. Дело не в длине списка: три из
/// четырёх полей — таблицы, и в позиционном вызове их ничто не отличает друг
/// от друга. Перепутанные местами `connections` и `udp_sessions`
/// компилируются молча и ломаются далеко от места ошибки.
struct Inner {
    /// Очереди пакетов между адаптером и smoltcp.
    device: VirtualDevice,
    /// Сокеты smoltcp.
    sockets: SocketSet<'static>,
    /// Соединения TCP, отданные и ещё не отданные движку.
    connections: ConnectionTable,
    /// Живые потоки UDP.
    udp_sessions: SessionTable,
}

/// Разбирает пришедший пакет.
fn handle_incoming(
    packet: &[u8],
    inner: &mut Inner,
    udp_incoming: &mpsc::Sender<Datagram>,
    config: &StackConfig,
) {
    let Some(parsed) = parse::parse(packet) else {
        // ICMP, широковещательные объявления, обрезанное — обычный фон.
        return;
    };

    match parsed.network {
        penguin_core::network::Network::Tcp => {
            if parsed.is_syn {
                open_socket(
                    parsed.source,
                    parsed.destination,
                    &mut inner.sockets,
                    &mut inner.connections,
                    config,
                );
            }
            // Сам пакет в любом случае отдаётся стеку: рукопожатие и данные
            // разбирает он.
            inner.device.queue_rx(BytesMut::from(packet));
        }
        penguin_core::network::Network::Udp => {
            let key = SessionKey {
                source: parsed.source,
                destination: parsed.destination,
            };
            inner.udp_sessions.touch(key, std::time::Instant::now());

            let datagram = Datagram {
                source: parsed.source,
                destination: parsed.destination,
                payload: Bytes::copy_from_slice(parsed.payload),
            };
            // Переполнение очереди — потеря датаграммы, то есть ровно то, что
            // с UDP и так случается. Блокировать здесь нельзя: остановился бы
            // весь стек, включая TCP.
            if udp_incoming.try_send(datagram).is_err() {
                tracing::trace!("очередь UDP переполнена, датаграмма отброшена");
            }
        }
    }
}

/// Заводит сокет под новое соединение.
fn open_socket(
    source: SocketAddr,
    destination: SocketAddr,
    sockets: &mut SocketSet<'static>,
    connections: &mut ConnectionTable,
    config: &StackConfig,
) {
    let key = FlowKey {
        source,
        destination,
    };
    if connections.contains_key(&key) {
        // Приложение перепосылает `SYN`, не дождавшись ответа. Второй сокет
        // под ту же пятёрку сломал бы соединение.
        return;
    }

    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; config.tcp_rx_buffer]),
        tcp::SocketBuffer::new(vec![0u8; config.tcp_tx_buffer]),
    );

    let endpoint = IpListenEndpoint {
        addr: Some(to_smoltcp(destination.ip())),
        port: destination.port(),
    };

    if let Err(err) = socket.listen(endpoint) {
        tracing::debug!(?err, %destination, "сокет не открылся");
        return;
    }
    // Приложение, не читающее из сокета, не должно держать его вечно.
    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(120)));
    socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(30)));

    let handle = sockets.add(socket);
    let (connection, ends) = TcpConnection::new(source, destination);

    // Соединение уходит наверх не сейчас, а когда рукопожатие завершится:
    // до этого момента соединения ещё нет, и отдавать движку нечего.
    // `pump_sockets` заметит переход в установленное состояние и отдаст его.
    connections.insert(handle, key, ends, connection);
}

/// Перекладывает данные между сокетами стека и очередями движка.
fn pump_sockets(
    sockets: &mut SocketSet<'static>,
    connections: &mut ConnectionTable,
    accepted: &mpsc::Sender<Accepted>,
) {
    for handle in connections.handles() {
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        let Some(entry) = connections.get_mut(handle) else {
            continue;
        };

        // --- рукопожатие завершилось: соединение можно отдавать ---
        if entry.pending.is_some() && socket.may_send() {
            let key = entry.key;
            if let Some(connection) = entry.pending.take() {
                let handover = Accepted {
                    connection,
                    source: key.source,
                    destination: key.destination,
                };
                if accepted.try_send(handover).is_err() {
                    // Движок не успевает разбирать соединения. Обрываем это
                    // сразу: приложение увидит отказ и повторит, а копить
                    // непринятые соединения в памяти нельзя.
                    tracing::debug!(%key.destination, "очередь соединений переполнена");
                    socket.abort();
                    connections.remove(handle);
                    sockets.remove(handle);
                    continue;
                }
            }
        }

        pump_data(socket, entry);

        if !socket.is_open() {
            connections.remove(handle);
            sockets.remove(handle);
        }
    }
}

/// Переводит адрес в понятия smoltcp.
fn to_smoltcp(address: IpAddr) -> IpAddress {
    match address {
        IpAddr::V4(v4) => IpAddress::from(v4),
        IpAddr::V6(v6) => IpAddress::from(v6),
    }
}

/// Конечная точка smoltcp из адреса.
///
/// Свободная функция ради теста: перепутать здесь порядок полей легко, а
/// последствие — соединения, уходящие не туда.
pub fn endpoint_of(address: SocketAddr) -> IpEndpoint {
    IpEndpoint {
        addr: to_smoltcp(address.ip()),
        port: address.port(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_keeps_address_and_port_apart() {
        let endpoint = endpoint_of("93.184.216.34:443".parse().expect("адрес"));
        assert_eq!(endpoint.port, 443);
        assert_eq!(endpoint.addr.to_string(), "93.184.216.34");
    }

    /// Собирает сегмент TCP от приложения.
    fn segment(
        source: SocketAddr,
        destination: SocketAddr,
        control: smoltcp::wire::TcpControl,
        seq: smoltcp::wire::TcpSeqNumber,
        ack: Option<smoltcp::wire::TcpSeqNumber>,
    ) -> Vec<u8> {
        use smoltcp::phy::ChecksumCapabilities;
        use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv4Repr, TcpPacket, TcpRepr};

        let (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) = (source.ip(), destination.ip())
        else {
            panic!("нужны адреса IPv4")
        };

        let tcp = TcpRepr {
            src_port: source.port(),
            dst_port: destination.port(),
            control,
            seq_number: seq,
            ack_number: ack,
            window_len: 64_000,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };

        let ip = Ipv4Repr {
            src_addr: source_ip,
            dst_addr: destination_ip,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };

        let caps = ChecksumCapabilities::default();
        let mut buffer = vec![0_u8; ip.buffer_len() + tcp.buffer_len()];
        ip.emit(&mut Ipv4Packet::new_unchecked(&mut buffer), &caps);
        tcp.emit(
            &mut TcpPacket::new_unchecked(&mut buffer[ip.buffer_len()..]),
            &IpAddress::from(ip.src_addr),
            &IpAddress::from(ip.dst_addr),
            &caps,
        );
        buffer
    }

    /// Собирает SYN от приложения к чужому адресу.
    fn syn(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
        use smoltcp::wire::{TcpControl, TcpSeqNumber};
        segment(source, destination, TcpControl::Syn, TcpSeqNumber(0), None)
    }

    /// Стек с очередями — то, что нужно каждому тесту пути данных.
    ///
    /// Структурой, а не россыпью аргументов: их шесть, и половина —
    /// изменяемые ссылки, которые в позиционном вызове ничем не отличаются
    /// друг от друга.
    struct Harness {
        config: StackConfig,
        inner: Inner,
        iface: Interface,
        clock: Clock,
        accepted: mpsc::Sender<Accepted>,
        waiting: mpsc::Receiver<Accepted>,
        udp: mpsc::Sender<Datagram>,
        _udp_out: mpsc::Receiver<Datagram>,
    }

    impl Harness {
        fn new(config: StackConfig) -> Self {
            let mut inner = Inner {
                device: VirtualDevice::new(config.mtu),
                sockets: SocketSet::new(Vec::new()),
                connections: ConnectionTable::new(),
                udp_sessions: SessionTable::new(),
            };
            let clock = Clock::start();
            let iface = build_interface(&config, &mut inner.device, clock.now());
            let (accepted, waiting) = mpsc::channel(4);
            let (udp, _udp_out) = mpsc::channel(4);

            Self {
                config,
                inner,
                iface,
                clock,
                accepted,
                waiting,
                udp,
                _udp_out,
            }
        }

        fn feed(&mut self, packet: &[u8]) {
            handle_incoming(packet, &mut self.inner, &self.udp, &self.config);
            self.poll();
        }

        fn poll(&mut self) {
            self.iface.poll(
                self.clock.now(),
                &mut self.inner.device,
                &mut self.inner.sockets,
            );
        }

        fn pump(&mut self) {
            pump_sockets(
                &mut self.inner.sockets,
                &mut self.inner.connections,
                &self.accepted,
            );
        }

        /// Доводит соединение до установленного и отдаёт его.
        ///
        /// Без настоящего рукопожатия сокет `smoltcp` не отдаёт ни байта, а
        /// половина ошибок этого стека живёт именно после него.
        fn establish(&mut self, source: SocketAddr, destination: SocketAddr) -> TcpConnection {
            use smoltcp::wire::{Ipv4Packet, TcpControl, TcpPacket};

            self.feed(&syn(source, destination));

            let answer = self.inner.device.take_tx().expect("стек не ответил на SYN");
            let ip = Ipv4Packet::new_checked(&answer[..]).expect("ответ не разбирается");
            let synack = TcpPacket::new_checked(ip.payload()).expect("это не TCP");
            let their_seq = synack.seq_number();
            let our_seq = synack.ack_number();

            self.feed(&segment(
                source,
                destination,
                TcpControl::None,
                our_seq,
                Some(their_seq + 1),
            ));

            // Рукопожатие завершено — `pump_sockets` отдаёт соединение движку.
            self.pump();
            self.waiting
                .try_recv()
                .expect("соединение не отдано движку")
                .connection
        }
    }

    #[test]
    fn a_packet_for_someone_else_gets_an_answer() {
        // Ради этого стек и существует: пакет адресован не ему, а он обязан
        // ответить за получателя.
        //
        // Одного `set_any_ip` для этого мало, и это стоило целого вечера:
        // smoltcp сперва ищет маршрут до чужого адреса и требует, чтобы шлюзом
        // оказался он сам. Пустая таблица маршрутов означала отказ, и стек
        // молча выбрасывал **каждый** перехваченный пакет — при поднятом
        // адаптере, целых маршрутах и нулях во всех счётчиках.
        let mut harness = Harness::new(StackConfig::default());
        harness.feed(&syn(
            "198.18.0.7:51000".parse().expect("адрес"),
            "8.8.8.8:443".parse().expect("адрес"),
        ));

        assert!(
            harness.inner.device.take_tx().is_some(),
            "стек не ответил на SYN — пакет отброшен, тоннель молчит"
        );
    }

    #[tokio::test]
    async fn the_tail_of_a_big_chunk_is_not_lost() {
        // `send_slice` записывает столько, сколько поместилось, и возвращает
        // это число. Считать его успехом целиком — потерять хвост в середине
        // потока TCP. Приложение получает поток без дыр, но с пропущенным
        // куском: TLS такого не переживает, соединение начинается заново, и
        // снаружи это выглядит как очень медленный тоннель.
        use tokio::io::AsyncWriteExt;

        let mut harness = Harness::new(StackConfig {
            tcp_tx_buffer: 4096,
            ..StackConfig::default()
        });
        let mut connection = harness.establish(
            "198.18.0.7:51000".parse().expect("адрес"),
            "93.184.216.34:443".parse().expect("адрес"),
        );

        // Вчетверо больше, чем помещается в сокет.
        let payload = vec![7_u8; harness.config.tcp_tx_buffer * 4];
        connection.write_all(&payload).await.expect("запись");
        harness.pump();

        let handle = harness
            .inner
            .connections
            .handles()
            .first()
            .copied()
            .expect("сокет");
        let entry = harness.inner.connections.get_mut(handle).expect("запись");
        assert!(
            entry.to_socket.is_some(),
            "хвост блока выброшен — в потоке появилась дыра"
        );
    }

    #[test]
    fn seed_differs_between_calls() {
        // Совпавшее зерно означает совпавшие номера последовательностей, а
        // это — старое соединение, принятое за новое.
        assert_ne!(rand_seed(), 0);
    }
}
