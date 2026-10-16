//! Главный цикл исходящей стороны: запросы в соединения, пакеты наружу.
//!
//! Зеркало `stack::run`: там пакеты превращаются в принятые соединения, здесь запросы — в открытые.
//!
//! ```text
//!                    ┌──────────────── одна задача ────────────────┐
//!   запрос ────────► │  сокет ──► smoltcp ──► устройство           │
//!   поток  ◄──────── │                             │               │
//!   датаграмма ────► │  свой порт ──► пакет ───────┤               │
//!                    └─────────────────────────────┼───────────────┘
//!                                                  ▼
//!                                        интерфейс тоннеля
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use penguin_tun::TunDevice;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::config::StackConfig;
use crate::device::VirtualDevice;
use crate::ip::parse;
use crate::poll::{Clock, clamp_delay};
use crate::stack::{Datagram, endpoint_of};
use crate::tcp::conn::TcpConnection;
use crate::tcp::pump::pump_data;
use crate::tcp::table::{ConnectionTable, FlowKey};
use crate::udp::session::build_datagram;

use super::connect::{ConnectError, Request};
use super::nat::{Flow, PortPool, UdpNat};

/// Срок рукопожатия; свой, а не таймаут smoltcp, чтобы отличать «отказали» от «не дошло».
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Как часто убирать молчащие потоки UDP.
const SWEEP_EVERY: Duration = Duration::from_secs(1);

/// Пакетов из тоннеля за один заход.
const RX_BATCH: usize = 64;

/// Ожидающий ответа запрос.
struct Pending {
    reply: oneshot::Sender<Result<TcpConnection, ConnectError>>,
    destination: SocketAddr,
    deadline: Instant,
}

/// Изменяемая начинка цикла.
struct Inner {
    device: VirtualDevice,
    sockets: SocketSet<'static>,
    connections: ConnectionTable,
    /// Запросы, на которые ещё не ответили.
    replies: HashMap<SocketHandle, Pending>,
    /// Свои порты TCP.
    tcp_ports: PortPool,
    /// Свои порты UDP.
    udp_ports: PortPool,
    /// Кому вернуть ответ на датаграмму.
    nat: UdpNat,
}

/// Крутит цикл, пока его не отменят или пока интерфейс не закроется.
pub async fn run(
    device: Box<dyn TunDevice>,
    config: StackConfig,
    cancel: CancellationToken,
    mut requests: mpsc::Receiver<Request>,
    mut udp_from_engine: mpsc::Receiver<Datagram>,
    udp_to_engine: mpsc::Sender<Datagram>,
) {
    let clock = Clock::start();
    let mut inner = Inner {
        device: VirtualDevice::new(config.mtu),
        sockets: SocketSet::new(Vec::new()),
        connections: ConnectionTable::new(),
        replies: HashMap::new(),
        tcp_ports: PortPool::new(),
        udp_ports: PortPool::new(),
        nat: UdpNat::new(),
    };
    let wake = inner.connections.wake();
    let mut iface = build_interface(&config, &mut inner.device, clock.now());
    let mut last_sweep = Instant::now();
    // Отпущенная движком очередь выключается: открытые потоки обязаны дожить.
    let mut requests_open = true;
    let mut udp_open = true;

    loop {
        tokio::select! {
            biased;

            () = cancel.cancelled() => break,

            packet = device.recv() => match packet {
                Ok(packet) => {
                    handle_incoming(packet, &mut inner, &udp_to_engine);
                    for _ in 0..RX_BATCH {
                        let Some(packet) = device.try_recv() else { break };
                        handle_incoming(packet, &mut inner, &udp_to_engine);
                    }
                }
                Err(err) => {
                    tracing::debug!(%err, "интерфейс закрыт, исходящий стек останавливается");
                    break;
                }
            },

            request = requests.recv(), if requests_open => match request {
                Some(request) => open_socket(request, &mut inner, &mut iface, &config),
                None => requests_open = false,
            },

            datagram = udp_from_engine.recv(), if udp_open => match datagram {
                Some(datagram) => send_datagram(datagram, &mut inner, &config),
                None => udp_open = false,
            },

            () = wake.notified() => {}

            () = tokio::time::sleep(clamp_delay(
                iface.poll_delay(clock.now(), &inner.sockets)
            )) => {}
        }

        let now = clock.now();
        iface.poll(now, &mut inner.device, &mut inner.sockets);
        let instant = Instant::now();
        pump_sockets(&mut inner, instant);
        iface.poll(now, &mut inner.device, &mut inner.sockets);

        if instant.duration_since(last_sweep) >= SWEEP_EVERY {
            inner.nat.expire(&mut inner.udp_ports, instant);
            last_sweep = instant;
        }

        while let Some(packet) = inner.device.take_tx() {
            if let Err(err) = device.send(&packet).await {
                tracing::debug!(%err, "пакет не ушёл в тоннель");
            }
        }

        if !requests_open && !udp_open && inner.connections.is_empty() {
            break;
        }
    }

    // Незавершённые запросы обязаны получить ответ.
    for (_, pending) in inner.replies.drain() {
        let _ = pending.reply.send(Err(ConnectError::Stopped));
    }
    let _ = device.close().await;
    tracing::info!("исходящий стек остановлен");
}

/// Собирает интерфейс smoltcp; в отличие от входящего, без `any_ip`: мы обычный узел со своим адресом.
fn build_interface(
    config: &StackConfig,
    device: &mut VirtualDevice,
    now: smoltcp::time::Instant,
) -> Interface {
    let mut iface_config = Config::new(HardwareAddress::Ip);
    iface_config.random_seed = crate::stack::rand_seed();

    let mut iface = Interface::new(iface_config, device, now);

    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::from(config.ipv4.0), config.ipv4.1));
        if let Some((address, prefix)) = config.ipv6 {
            let _ = addrs.push(IpCidr::new(IpAddress::from(address), prefix));
        }
    });

    // Без маршрута по умолчанию smoltcp не шлёт ничего за пределы подсети; шлюз — свой адрес.
    if let Err(err) = iface.routes_mut().add_default_ipv4_route(config.ipv4.0) {
        tracing::error!(?err, "исходящий стек не отправит ни одного пакета");
    }
    if let Some((address, _)) = config.ipv6
        && let Err(err) = iface.routes_mut().add_default_ipv6_route(address)
    {
        tracing::error!(?err, "исходящий стек не отправит ни одного пакета IPv6");
    }

    iface
}

/// Заводит сокет под новый запрос.
fn open_socket(request: Request, inner: &mut Inner, iface: &mut Interface, config: &StackConfig) {
    let destination = request.destination;

    let Some(local_ip) = local_address(destination.ip(), config) else {
        let _ = request
            .reply
            .send(Err(ConnectError::NoAddress(destination)));
        return;
    };
    let Some(port) = inner.tcp_ports.take() else {
        let _ = request.reply.send(Err(ConnectError::NoPorts));
        return;
    };

    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; config.tcp_rx_buffer]),
        tcp::SocketBuffer::new(vec![0u8; config.tcp_tx_buffer]),
    );
    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(120)));
    socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(30)));

    if let Err(err) = socket.connect(iface.context(), endpoint_of(destination), port) {
        tracing::debug!(?err, %destination, "сокет не открылся");
        inner.tcp_ports.release(port);
        let _ = request
            .reply
            .send(Err(ConnectError::NoAddress(destination)));
        return;
    }

    let source = SocketAddr::new(local_ip, port);
    let handle = inner.sockets.add(socket);
    let (connection, ends) = TcpConnection::new(source, destination);
    inner.connections.insert(
        handle,
        FlowKey {
            source,
            destination,
        },
        ends,
        connection,
    );
    inner.replies.insert(
        handle,
        Pending {
            reply: request.reply,
            destination,
            deadline: Instant::now() + CONNECT_TIMEOUT,
        },
    );
}

/// Отдаёт готовые соединения, отвечает на неудавшиеся, перекладывает данные.
fn pump_sockets(inner: &mut Inner, now: Instant) {
    let mut dead = Vec::new();

    for (handle, entry) in inner.connections.iter_mut() {
        let socket = inner.sockets.get_mut::<tcp::Socket>(handle);

        if entry.pending.is_some() {
            match settle(handle, socket, now, &mut inner.replies) {
                Some(Settled::Established(pending)) => {
                    if let Some(connection) = entry.pending.take()
                        && pending.reply.send(Ok(connection)).is_err()
                    {
                        // Движок передумал ждать.
                        socket.abort();
                    }
                }
                Some(Settled::Failed(pending)) => {
                    socket.abort();
                    let error = failure(&pending, now);
                    let _ = pending.reply.send(Err(error));
                }
                None => {}
            }
        }

        pump_data(socket, entry);

        if !socket.is_open() {
            dead.push(handle);
        }
    }

    for handle in dead {
        if let Some(entry) = inner.connections.remove(handle) {
            inner.tcp_ports.release(entry.key.source.port());
        }
        // Закрылся, не дождавшись рукопожатия, и `settle` не застал: иначе запрос повиснет.
        if let Some(pending) = inner.replies.remove(&handle) {
            let error = failure(&pending, now);
            let _ = pending.reply.send(Err(error));
        }
        inner.sockets.remove(handle);
    }
}

/// Что стало с ожидающим запросом.
enum Settled {
    /// Рукопожатие прошло.
    Established(Pending),
    /// Соединения не будет.
    Failed(Pending),
}

/// Решает судьбу ожидающего запроса; `None` — рукопожатие ещё идёт.
fn settle(
    handle: SocketHandle,
    socket: &tcp::Socket<'_>,
    now: Instant,
    replies: &mut HashMap<SocketHandle, Pending>,
) -> Option<Settled> {
    let pending = replies.get(&handle)?;

    if socket.may_send() {
        return replies.remove(&handle).map(Settled::Established);
    }
    if !socket.is_open() || now >= pending.deadline {
        return replies.remove(&handle).map(Settled::Failed);
    }
    None
}

/// Отказ или молчание: различаются по нашему сроку, smoltcp причину закрытия не сообщает.
fn failure(pending: &Pending, now: Instant) -> ConnectError {
    if now >= pending.deadline {
        ConnectError::TimedOut(pending.destination)
    } else {
        ConnectError::Refused(pending.destination)
    }
}

/// Разбирает пакет из тоннеля; владение нужно, чтобы отдать TCP и срезать UDP без копии.
fn handle_incoming(packet: BytesMut, inner: &mut Inner, udp_to_engine: &mpsc::Sender<Datagram>) {
    let Some(parsed) = parse::parse(&packet) else {
        return;
    };

    match parsed.network {
        penguin_core::network::Network::Tcp => inner.device.queue_rx(packet),
        penguin_core::network::Network::Udp => {
            // Чужой порт или адрес отправителя — чужой ответ либо подделка.
            let Some(flow) =
                inner
                    .nat
                    .flow_of(parsed.destination.port(), parsed.source, Instant::now())
            else {
                tracing::trace!(port = parsed.destination.port(), "датаграмма ничья");
                return;
            };

            let datagram = Datagram {
                source: flow.app,
                destination: flow.destination,
                payload: Bytes::copy_from_slice(parsed.payload),
            };
            if udp_to_engine.try_send(datagram).is_err() {
                tracing::trace!("очередь UDP переполнена, датаграмма отброшена");
            }
        }
    }
}

/// Собирает и ставит в очередь датаграмму движка.
fn send_datagram(datagram: Datagram, inner: &mut Inner, config: &StackConfig) {
    let Some(local_ip) = local_address(datagram.destination.ip(), config) else {
        tracing::trace!(%datagram.destination, "у интерфейса нет адреса этого семейства");
        return;
    };

    let flow = Flow {
        app: datagram.source,
        destination: datagram.destination,
    };
    let Some(port) = inner
        .nat
        .port_for(flow, &mut inner.udp_ports, Instant::now())
    else {
        tracing::debug!("свободных портов UDP не осталось, датаграмма отброшена");
        return;
    };

    let source = SocketAddr::new(local_ip, port);
    let Some(packet) = build_datagram(source, datagram.destination, &datagram.payload) else {
        return;
    };

    // Фрагментации нет: слишком длинную датаграмму молча не режем.
    if packet.len() > usize::from(config.mtu) {
        tracing::debug!(
            length = packet.len(),
            mtu = config.mtu,
            "датаграмма длиннее MTU, отброшена"
        );
        return;
    }

    inner.device.queue_tx(packet);
}

/// Свой адрес того же семейства, что у назначения.
fn local_address(destination: IpAddr, config: &StackConfig) -> Option<IpAddr> {
    match destination {
        IpAddr::V4(_) => Some(IpAddr::V4(config.ipv4.0)),
        IpAddr::V6(_) => config.ipv6.map(|(address, _)| IpAddr::V6(address)),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    fn config() -> StackConfig {
        StackConfig::default()
    }

    #[test]
    fn a_v6_destination_needs_a_v6_address_on_the_interface() {
        let v4: IpAddr = "93.184.216.34".parse().expect("адрес");
        let v6: IpAddr = "2001:db8::1".parse().expect("адрес");

        assert!(local_address(v4, &config()).is_some());
        assert!(local_address(v6, &config()).is_none());

        let with_v6 = StackConfig {
            ipv6: Some((Ipv6Addr::LOCALHOST, 64)),
            ..config()
        };
        assert!(local_address(v6, &with_v6).is_some());
    }

    #[test]
    fn the_local_address_is_never_of_the_wrong_family() {
        let with_v6 = StackConfig {
            ipv6: Some((Ipv6Addr::LOCALHOST, 64)),
            ..config()
        };
        let v4: IpAddr = "8.8.8.8".parse().expect("адрес");
        assert!(matches!(local_address(v4, &with_v6), Some(IpAddr::V4(_))));
    }

    fn pending(deadline: Instant) -> Pending {
        let (reply, _answer) = oneshot::channel();
        Pending {
            reply,
            destination: "93.184.216.34:443".parse().expect("адрес"),
            deadline,
        }
    }

    #[test]
    fn a_closed_socket_before_the_deadline_reads_as_a_refusal() {
        let now = Instant::now();
        let error = failure(&pending(now + Duration::from_secs(5)), now);
        assert!(matches!(error, ConnectError::Refused(_)));
    }

    #[test]
    fn an_expired_deadline_reads_as_silence() {
        let now = Instant::now();
        let error = failure(&pending(now - Duration::from_secs(1)), now);
        assert!(matches!(error, ConnectError::TimedOut(_)));
    }

    #[test]
    fn the_connect_timeout_is_shorter_than_the_socket_timeout() {
        const { assert!(CONNECT_TIMEOUT.as_secs() < 120) };
    }
}
