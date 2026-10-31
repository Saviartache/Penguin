//! Опознанный `CONNECT` и канал датаграмм по HTTP/2: TCP и UDP к цели через `target`.

use bytes::{Bytes, BytesMut};
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use http::{Response, StatusCode};
use penguin_pingwin::tcp::io::{H2Recv, send_all};
use penguin_pingwin::wire::capsule;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::target;

/// Сколько датаграмм ждёт отправки в каждую сторону, прежде чем лишние теряются.
const DATAGRAM_QUEUE: usize = 256;

/// Соединяет клиента с целью и переливает байты в обе стороны.
pub(crate) async fn stream(authority: &str, body: RecvStream, mut respond: SendResponse<Bytes>) {
    let upstream = match target::connect(authority).await {
        Ok(upstream) => upstream,
        Err(err) => {
            tracing::debug!(target = authority, %err, "цель недоступна");
            refuse(respond, &err.to_string()).await;
            return;
        }
    };
    let send = match respond.send_response(ok(), false) {
        Ok(send) => send,
        Err(err) => {
            tracing::debug!(%err, "подтверждение не ушло");
            return;
        }
    };
    if let Err(err) = pump(send, H2Recv::new(body), upstream).await {
        tracing::debug!(target = authority, %err, "поток оборвался");
    }
}

/// Переливает до конца обеих сторон; ошибка одной обрывает обе.
async fn pump(
    mut send: SendStream<Bytes>,
    mut recv: H2Recv,
    upstream: TcpStream,
) -> std::io::Result<()> {
    let (mut from_target, mut to_target) = upstream.into_split();

    let up = async {
        while let Some(chunk) = recv.chunk().await? {
            to_target.write_all(&chunk).await?;
        }
        to_target.shutdown().await
    };
    let down = async {
        let mut buffer = BytesMut::new();
        loop {
            buffer.reserve(target::COPY_BUFFER);
            if from_target.read_buf(&mut buffer).await? == 0 {
                break;
            }
            send_all(&mut send, buffer.split().freeze()).await?;
        }
        send.send_data(Bytes::new(), true)
            .map_err(std::io::Error::other)
    };

    tokio::pin!(up, down);
    tokio::select! {
        done = &mut up => { done?; down.await }
        done = &mut down => { done?; up.await }
    }
}

/// `502` с причиной в теле.
async fn refuse(mut respond: SendResponse<Bytes>, reason: &str) {
    let response = Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(());
    let Ok(response) = response else {
        return;
    };
    let sent = async {
        let mut send = respond.send_response(response, false)?;
        send_all(&mut send, Bytes::copy_from_slice(reason.as_bytes())).await?;
        send.send_data(Bytes::new(), true)?;
        anyhow::Ok(())
    };
    if let Err(err) = sent.await {
        tracing::trace!(%err, "отказ не ушёл");
    }
}

fn ok() -> Response<()> {
    let mut response = Response::new(());
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert("capsule-protocol", http::HeaderValue::from_static("?1"));
    response
}

/// Датаграммный канал: капсулы `DATAGRAM` в теле потока, в обе стороны.
pub(crate) async fn datagram(body: RecvStream, mut respond: SendResponse<Bytes>) {
    let socket = match target::bind_udp().await {
        Ok(socket) => socket,
        Err(err) => {
            tracing::debug!(%err, "не открылся сокет для датаграмм");
            refuse(respond, "сокет для датаграмм не открылся").await;
            return;
        }
    };
    let mut send = match respond.send_response(ok(), false) {
        Ok(send) => send,
        Err(err) => {
            tracing::debug!(%err, "подтверждение не ушло");
            return;
        }
    };

    let (to_target, from_client) = mpsc::channel(DATAGRAM_QUEUE);
    let (to_client, mut replies) = mpsc::channel::<Bytes>(DATAGRAM_QUEUE);

    let reading = async {
        let mut recv = H2Recv::new(body);
        let mut buffer = BytesMut::new();
        loop {
            loop {
                match capsule::decode(&mut buffer) {
                    Ok(Some(datagram)) => {
                        // Очередь полна — датаграмма теряется, как в сети.
                        let _ = to_target.try_send(datagram);
                    }
                    Ok(None) => break,
                    Err(err) => {
                        tracing::debug!(%err, "капсула не разобралась");
                        return;
                    }
                }
            }
            match recv.chunk().await {
                Ok(Some(chunk)) => buffer.extend_from_slice(&chunk),
                Ok(None) | Err(_) => return,
            }
        }
    };
    let writing = async {
        while let Some(frame) = replies.recv().await {
            if send_all(&mut send, frame).await.is_err() {
                return;
            }
        }
    };
    let reply = |payload: &[u8]| {
        let mut frame = Vec::with_capacity(payload.len() + 8);
        capsule::encode_into(payload, &mut frame);
        !matches!(
            to_client.try_send(Bytes::from(frame)),
            Err(mpsc::error::TrySendError::Closed(_))
        )
    };
    tokio::select! {
        () = target::nat(socket, from_client, reply) => {}
        () = reading => {}
        () = writing => {}
    }
}
