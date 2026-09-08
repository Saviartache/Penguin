//! Что сервер делает с открытым потоком и датаграммным каналом.
//!
//! ```text
//!  поток:      клиент ─► OPEN(адрес) ─► сюда ─► TcpStream ─► цель
//!  датаграммы: клиент ─► UDP(адрес)  ─► сюда ─► UdpSocket ─► цель
//! ```
//!
//! Имя цели разрешается **здесь**, а не у клиента: ради этого прокси и
//! существует. Отсюда же и запрет держать разрешённый адрес дольше одного
//! соединения — кэш имён на сервере означал бы, что два разных клиента
//! получают один ответ.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use penguin_core::address::{Address, SocketAddress};
use penguin_pingwin::mux::{DatagramRequest, StreamRequest};
use penguin_proto::datagram::ProxyDatagram;
use tokio::net::{TcpStream, UdpSocket};

/// Сколько ждать соединения с целью.
///
/// Дольше ждать бессмысленно: клиент к этому времени уже считает поток
/// зависшим (у него свой срок на подтверждение открытия).
const DIAL_LIMIT: Duration = Duration::from_secs(8);

/// Через сколько тишины закрывать датаграммный канал.
///
/// У UDP нет закрытия, и единственный способ освободить сокет — перестать
/// ждать. Минута покрывает и DNS, и QUIC с его периодическими посылками.
const UDP_IDLE: Duration = Duration::from_secs(60);

/// Наибольшая датаграмма, которую сервер принимает от цели.
const UDP_BUFFER: usize = 64 * 1024;

/// Соединяет клиента с целью и переливает байты в обе стороны.
pub async fn stream(request: StreamRequest) {
    let target = request.target().clone();

    let upstream = match tokio::time::timeout(DIAL_LIMIT, dial(&target)).await {
        Ok(Ok(upstream)) => upstream,
        Ok(Err(err)) => {
            tracing::debug!(target = %target.to_wire(), %err, "цель недоступна");
            let _ = request.reject(&err.to_string()).await;
            return;
        }
        Err(_) => {
            let _ = request.reject("цель не ответила за отведённое время").await;
            return;
        }
    };

    let mut client = match request.accept().await {
        Ok(client) => client,
        Err(err) => {
            tracing::debug!(%err, "подтверждение не ушло");
            return;
        }
    };
    let mut upstream = upstream;
    // Обе стороны читаются одновременно: иначе поток, из которого не читают,
    // остановил бы всю сессию (см. `penguin_pingwin::mux::session`).
    if let Err(err) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        tracing::debug!(target = %target.to_wire(), %err, "поток оборвался");
    }
}

/// Открывает соединение с целью, разрешая имя на этой стороне.
async fn dial(target: &SocketAddress) -> std::io::Result<TcpStream> {
    match &target.host {
        Address::Ip(ip) => TcpStream::connect(SocketAddr::new(*ip, target.port)).await,
        Address::Domain(domain) => TcpStream::connect((domain.as_str(), target.port)).await,
    }
}

/// Обслуживает датаграммный канал: один сокет на канал, адрес на посылке.
///
/// Один сокет, а не по одному на каждого собеседника: так же ведёт себя
/// обычный NAT, и приложению, которое шлёт запросы десяти серверам имён,
/// незачем платить десятью сокетами.
pub async fn datagram(request: DatagramRequest) {
    let socket = match UdpSocket::bind(("0.0.0.0", 0)).await {
        Ok(socket) => Arc::new(socket),
        Err(err) => {
            tracing::debug!(%err, "не открылся сокет для датаграмм");
            return;
        }
    };

    let channel: Arc<dyn ProxyDatagram> = match request.accept().await {
        Ok(channel) => Arc::new(channel),
        Err(err) => {
            tracing::debug!(%err, "подтверждение не ушло");
            return;
        }
    };

    let outgoing = tokio::spawn({
        let socket = Arc::clone(&socket);
        let channel = Arc::clone(&channel);
        async move { pump_out(&channel, &socket).await }
    });
    let incoming = tokio::spawn({
        let socket = Arc::clone(&socket);
        let channel = Arc::clone(&channel);
        async move { pump_in(&channel, &socket).await }
    });

    // Кончился любой из двух — канала больше нет: второй ждал бы вечно.
    tokio::select! {
        _ = outgoing => {}
        _ = incoming => {}
    }
    let _ = channel.close().await;
}

/// От клиента к цели.
async fn pump_out(channel: &Arc<dyn ProxyDatagram>, socket: &UdpSocket) {
    loop {
        let Ok(Ok((payload, target))) = tokio::time::timeout(UDP_IDLE, channel.recv_from()).await
        else {
            return;
        };
        let Some(addr) = resolve(&target).await else {
            tracing::debug!(target = %target.to_wire(), "имя не разрешилось");
            continue;
        };
        if socket.send_to(&payload, addr).await.is_err() {
            return;
        }
    }
}

/// От цели к клиенту.
async fn pump_in(channel: &Arc<dyn ProxyDatagram>, socket: &UdpSocket) {
    let mut buffer = vec![0u8; UDP_BUFFER];
    loop {
        let Ok(Ok((len, from))) =
            tokio::time::timeout(UDP_IDLE, socket.recv_from(&mut buffer)).await
        else {
            return;
        };
        let payload = Bytes::copy_from_slice(&buffer[..len]);
        let from = SocketAddress::ip(from.ip(), from.port());
        if channel.send_to(payload, &from).await.is_err() {
            return;
        }
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
