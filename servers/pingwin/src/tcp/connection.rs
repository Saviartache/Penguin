//! Одно соединение по TCP: TLS, HTTP/2, опознание, запросы. Опознаётся соединение, а не запрос.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use h2::server::SendResponse;
use h2::{Ping, PingPong, RecvStream};
use http::{Method, Request, Response, StatusCode, header};
use penguin_pingwin::tcp::io::send_all;
use penguin_pingwin::wire::keys::{EXPORTER_LABEL, KEY_LEN};
use penguin_pingwin::wire::{auth, tcp, udp};
use tokio::net::TcpStream;

use crate::admission;
use crate::cover;
use crate::server::Server;
use crate::tcp::{http1, relay};
use crate::tls::ALPN_H2;

/// Срок на TLS и приветствие HTTP/2: молчащий не держит задачу.
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(10);

/// Как часто проверять, что клиент на месте: у TCP мёртвое соединение молчит.
const KEEPALIVE: Duration = Duration::from_secs(30);

/// Сколько ждать ответа на пинг.
const PING_LIMIT: Duration = Duration::from_secs(15);

/// Общее для всех запросов соединения.
struct State {
    server: Arc<Server>,
    peer: SocketAddr,
    exporter: [u8; KEY_LEN],
    /// Имя опознанного пользователя.
    user: OnceLock<String>,
}

/// Обслуживает соединение до его конца.
pub(crate) async fn serve(server: Arc<Server>, tcp: TcpStream, peer: SocketAddr) {
    if let Err(err) = tcp.set_nodelay(true) {
        tracing::debug!(%peer, %err, "TCP_NODELAY не встал");
    }
    let tls = match tokio::time::timeout(HANDSHAKE_LIMIT, server.tcp.accept(tcp)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(err)) => {
            tracing::debug!(%peer, %err, "рукопожатие TLS не состоялось");
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, "рукопожатие TLS не уложилось в срок");
            return;
        }
    };
    let (_, session) = tls.get_ref();
    if session.alpn_protocol() != Some(ALPN_H2) {
        http1::serve(server.config.cover.as_deref(), tls).await;
        return;
    }
    let mut exporter = [0u8; KEY_LEN];
    if session
        .export_keying_material(&mut exporter, EXPORTER_LABEL, Some(b""))
        .is_err()
    {
        tracing::warn!(%peer, "экспорт ключей TLS не удался");
        return;
    }

    let handshake = h2::server::Builder::new()
        .initial_window_size(tcp::STREAM_WINDOW)
        .initial_connection_window_size(tcp::CONNECTION_WINDOW)
        .header_table_size(tcp::HEADER_TABLE)
        .max_header_list_size(tcp::MAX_HEADER_LIST)
        .max_send_buffer_size(tcp::SEND_BUFFER)
        .enable_connect_protocol()
        .handshake::<_, Bytes>(tls);
    let mut h2 = match tokio::time::timeout(HANDSHAKE_LIMIT, handshake).await {
        Ok(Ok(h2)) => h2,
        Ok(Err(err)) => {
            tracing::debug!(%peer, %err, "HTTP/2 не поднялся");
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, "HTTP/2 не поднялся в срок");
            return;
        }
    };

    let ping = h2.ping_pong();
    let state = Arc::new(State {
        server,
        peer,
        exporter,
        user: OnceLock::new(),
    });
    let requests = async {
        while let Some(accepted) = h2.accept().await {
            match accepted {
                Ok((request, respond)) => {
                    tokio::spawn(handle(Arc::clone(&state), request, respond));
                }
                Err(err) => {
                    tracing::debug!(%peer, %err, "соединение закрылось");
                    return;
                }
            }
        }
    };
    tokio::select! {
        () = requests => {}
        () = keepalive(ping) => tracing::debug!(%peer, "клиент не ответил на пинг"),
    }
}

/// Пингует, пока клиент отвечает.
async fn keepalive(ping: Option<PingPong>) {
    let Some(mut ping) = ping else {
        return std::future::pending().await;
    };
    loop {
        tokio::time::sleep(KEEPALIVE).await;
        match tokio::time::timeout(PING_LIMIT, ping.ping(Ping::opaque())).await {
            Ok(Ok(_pong)) => {}
            _ => return,
        }
    }
}

async fn handle(state: Arc<State>, request: Request<RecvStream>, respond: SendResponse<Bytes>) {
    if let Some(admitted) = admission::admit(&state.server, &state.exporter, &request) {
        if state.user.set(admitted.user.clone()).is_ok() {
            tracing::info!(peer = %state.peer, user = admitted.user, "клиент опознан по TCP");
        }
        accept(respond, &admitted.proof);
        return;
    }
    let root = state.server.config.cover.as_deref();
    if state.user.get().is_none() || request.method() != Method::CONNECT {
        serve_cover(root, &request, respond).await;
        return;
    }
    let protocol = request.extensions().get::<h2::ext::Protocol>();
    let authority = request.uri().authority().map(|a| a.as_str().to_owned());
    match (protocol.map(h2::ext::Protocol::as_str), authority) {
        (None, Some(authority)) => relay::stream(&authority, request.into_body(), respond).await,
        (Some(udp::PROTOCOL), _) if request.uri().path() == udp::PATH => {
            relay::datagram(request.into_body(), respond).await;
        }
        _ => serve_cover(root, &request, respond).await,
    }
}

fn accept(mut respond: SendResponse<Bytes>, proof: &str) {
    let response = Response::builder()
        .status(StatusCode::from_u16(auth::ACCEPTED).unwrap_or(StatusCode::NO_CONTENT))
        .header(auth::PROOF_HEADER, proof)
        .body(());
    let Ok(response) = response else {
        return;
    };
    if let Err(err) = respond.send_response(response, true) {
        tracing::debug!(%err, "ответ на опознание не ушёл");
    }
}

/// Сайт прикрытия, как и по HTTP/3.
async fn serve_cover<T>(
    root: Option<&std::path::Path>,
    request: &Request<T>,
    mut respond: SendResponse<Bytes>,
) {
    let (status, content_type, body) = cover::answer(root, request).await;
    let response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, body.len())
        .body(());
    let Ok(response) = response else {
        return;
    };
    let bodyless = request.method() == Method::HEAD || body.is_empty();
    let sent = async {
        let mut send = respond.send_response(response, bodyless)?;
        if !bodyless {
            send_all(&mut send, body).await?;
            send.send_data(Bytes::new(), true)?;
        }
        anyhow::Ok(())
    };
    if let Err(err) = sent.await {
        tracing::trace!(%err, "ответ прикрытия не ушёл");
    }
}
