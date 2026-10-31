//! Цели на стороне сервера: TCP до адреса и UDP-сокет канала. Имя цели разрешается здесь.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use penguin_core::address::{Address, SocketAddress};
use penguin_pingwin::wire::udp;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

/// Срок соединения с целью.
const DIAL_LIMIT: Duration = Duration::from_secs(8);

/// Через сколько тишины закрывать датаграммный канал: у UDP нет закрытия.
const UDP_IDLE: Duration = Duration::from_secs(60);

/// Наибольшая датаграмма, которую сервер принимает от цели.
const UDP_BUFFER: usize = 64 * 1024;

/// Сколько читать от цели за раз.
pub(crate) const COPY_BUFFER: usize = 32 * 1024;

/// Соединяется с `authority` (`host:port`) со сроком.
pub(crate) async fn connect(authority: &str) -> io::Result<TcpStream> {
    let target: SocketAddress = authority
        .parse()
        .map_err(|err| io::Error::other(format!("{err}")))?;
    tokio::time::timeout(DIAL_LIMIT, dial(&target))
        .await
        .unwrap_or_else(|_| Err(io::Error::other("цель не ответила за отведённое время")))
}

async fn dial(target: &SocketAddress) -> io::Result<TcpStream> {
    let stream = match &target.host {
        Address::Ip(ip) => TcpStream::connect(SocketAddr::new(*ip, target.port)).await?,
        Address::Domain(domain) => TcpStream::connect((domain.as_str(), target.port)).await?,
    };
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Сокет датаграммного канала: один на канал, адрес на посылке (как у NAT).
pub(crate) async fn bind_udp() -> io::Result<UdpSocket> {
    UdpSocket::bind(("0.0.0.0", 0)).await
}

/// Переливает датаграммы канала, пока не настанет тишина: от клиента — `incoming`
/// (содержимое `udp`), к нему — `reply` (то же содержимое; `false` — канал кончился).
pub(crate) async fn nat(
    socket: UdpSocket,
    mut incoming: mpsc::Receiver<Bytes>,
    mut reply: impl FnMut(&[u8]) -> bool,
) {
    let outgoing = async {
        while let Ok(Some(payload)) = tokio::time::timeout(UDP_IDLE, incoming.recv()).await {
            let Some((target, data)) = udp::decode(payload) else {
                continue;
            };
            let Some(addr) = resolve(&target).await else {
                tracing::debug!(target = %target.to_wire(), "имя не разрешилось");
                continue;
            };
            if socket.send_to(&data, addr).await.is_err() {
                return;
            }
        }
    };
    let returning = async {
        let mut buffer = vec![0u8; UDP_BUFFER];
        let mut payload = Vec::new();
        while let Ok(Ok((len, from))) =
            tokio::time::timeout(UDP_IDLE, socket.recv_from(&mut buffer)).await
        {
            if udp::encode_into(&SocketAddress::from(from), &buffer[..len], &mut payload).is_err() {
                continue;
            }
            if !reply(&payload) {
                return;
            }
        }
    };
    tokio::select! {
        () = outgoing => {}
        () = returning => {}
    }
}

/// Разрешает адрес цели. `None` — имя не разрешилось.
async fn resolve(target: &SocketAddress) -> Option<SocketAddr> {
    match &target.host {
        Address::Ip(ip) => Some(SocketAddr::new(*ip, target.port)),
        Address::Domain(domain) => tokio::net::lookup_host((domain.as_str(), target.port))
            .await
            .ok()?
            .next(),
    }
}
