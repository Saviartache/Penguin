//! Опознанный `CONNECT` и канал датаграмм: TCP и UDP к цели. Имя цели разрешается здесь.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::{Response, StatusCode};
use penguin_core::address::{Address, SocketAddress};
use penguin_pingwin::wire::udp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::cover::Stream;

/// Срок соединения с целью.
const DIAL_LIMIT: Duration = Duration::from_secs(8);

/// Через сколько тишины закрывать датаграммный канал: у UDP нет закрытия.
const UDP_IDLE: Duration = Duration::from_secs(60);

/// Наибольшая датаграмма, которую сервер принимает от цели.
const UDP_BUFFER: usize = 64 * 1024;

/// Сколько читать от цели за раз.
const COPY_BUFFER: usize = 32 * 1024;

/// Соединяет клиента с целью и переливает байты в обе стороны.
pub async fn stream(authority: &str, mut stream: Stream) {
    let dialed = match authority.parse::<SocketAddress>() {
        Ok(target) => tokio::time::timeout(DIAL_LIMIT, dial(&target))
            .await
            .unwrap_or_else(|_| {
                Err(std::io::Error::other(
                    "цель не ответила за отведённое время",
                ))
            }),
        Err(err) => Err(std::io::Error::other(err.to_string())),
    };
    let upstream = match dialed {
        Ok(upstream) => upstream,
        Err(err) => {
            tracing::debug!(target = authority, %err, "цель недоступна");
            refuse(stream, &err.to_string()).await;
            return;
        }
    };
    if let Err(err) = stream.send_response(ok()).await {
        tracing::debug!(%err, "подтверждение не ушло");
        return;
    }
    if let Err(err) = pump(stream, upstream).await {
        tracing::debug!(target = authority, %err, "поток оборвался");
    }
}

/// Переливает до конца обеих сторон; ошибка одной обрывает обе.
async fn pump(stream: Stream, upstream: TcpStream) -> anyhow::Result<()> {
    let (mut send, mut recv) = stream.split();
    let (mut from_target, mut to_target) = upstream.into_split();

    let up = async {
        while let Some(mut chunk) = recv.recv_data().await? {
            to_target.write_all_buf(&mut chunk).await?;
        }
        to_target.shutdown().await?;
        anyhow::Ok(())
    };
    let down = async {
        let mut buffer = BytesMut::new();
        loop {
            buffer.reserve(COPY_BUFFER);
            if from_target.read_buf(&mut buffer).await? == 0 {
                break;
            }
            send.send_data(buffer.split().freeze()).await?;
        }
        send.finish().await?;
        anyhow::Ok(())
    };

    tokio::pin!(up, down);
    tokio::select! {
        done = &mut up => { done?; down.await }
        done = &mut down => { done?; up.await }
    }
}

/// Открывает соединение с целью, разрешая имя на этой стороне.
async fn dial(target: &SocketAddress) -> std::io::Result<TcpStream> {
    let stream = match &target.host {
        Address::Ip(ip) => TcpStream::connect(SocketAddr::new(*ip, target.port)).await?,
        Address::Domain(domain) => TcpStream::connect((domain.as_str(), target.port)).await?,
    };
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// `502` с причиной в теле.
async fn refuse(mut stream: Stream, reason: &str) {
    let response = Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(());
    let Ok(response) = response else {
        return;
    };
    let sent = async {
        stream.send_response(response).await?;
        stream
            .send_data(Bytes::copy_from_slice(reason.as_bytes()))
            .await?;
        stream.finish().await
    };
    if let Err(err) = sent.await {
        tracing::trace!(%err, "отказ не ушёл");
    }
}

fn ok() -> Response<()> {
    let mut response = Response::new(());
    *response.status_mut() = StatusCode::OK;
    response
}

/// Датаграммный канал: один сокет на канал, адрес на посылке (как у NAT).
pub async fn datagram(
    mut stream: Stream,
    quic: quinn::Connection,
    mut incoming: mpsc::Receiver<Bytes>,
) {
    let stream_id = stream.id().into_inner();
    let socket = match UdpSocket::bind(("0.0.0.0", 0)).await {
        Ok(socket) => socket,
        Err(err) => {
            tracing::debug!(%err, "не открылся сокет для датаграмм");
            refuse(stream, "сокет для датаграмм не открылся").await;
            return;
        }
    };
    if let Err(err) = stream.send_response(ok()).await {
        tracing::debug!(%err, "подтверждение не ушло");
        return;
    }

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
            match quic.send_datagram(udp::datagram::encode(stream_id, &payload)) {
                Ok(()) | Err(quinn::SendDatagramError::TooLarge) => {}
                Err(_) => return,
            }
        }
    };
    let closed = async { while let Ok(Some(_)) = stream.recv_data().await {} };

    tokio::select! {
        () = outgoing => {}
        () = returning => {}
        () = closed => {}
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
