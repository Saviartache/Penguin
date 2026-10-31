//! Опознанный `CONNECT` и канал датаграмм по HTTP/3: TCP и UDP к цели через `target`.

use bytes::{Bytes, BytesMut};
use http::{Response, StatusCode};
use penguin_pingwin::wire::udp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::cover::Stream;
use crate::target;

/// Соединяет клиента с целью и переливает байты в обе стороны.
pub async fn stream(authority: &str, mut stream: Stream) {
    let upstream = match target::connect(authority).await {
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
            buffer.reserve(target::COPY_BUFFER);
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

/// Датаграммный канал: датаграммы QUIC с номером потока запроса.
pub async fn datagram(
    mut stream: Stream,
    quic: quinn::Connection,
    incoming: mpsc::Receiver<Bytes>,
) {
    let stream_id = stream.id().into_inner();
    let socket = match target::bind_udp().await {
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

    let reply = |payload: &[u8]| {
        matches!(
            quic.send_datagram(udp::datagram::encode(stream_id, payload)),
            Ok(()) | Err(quinn::SendDatagramError::TooLarge)
        )
    };
    let closed = async { while let Ok(Some(_)) = stream.recv_data().await {} };
    tokio::select! {
        () = target::nat(socket, incoming, reply) => {}
        () = closed => {}
    }
}
