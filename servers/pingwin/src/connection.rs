//! Одно соединение: HTTP/3, опознание, запросы и датаграммы. Опознаётся соединение, а не запрос.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};

use bytes::Bytes;
use h3::server::RequestResolver;
use http::{Method, Request, Response, StatusCode};
use penguin_pingwin::wire::keys::{EXPORTER_LABEL, KEY_LEN};
use penguin_pingwin::wire::{auth, udp};
use tokio::sync::mpsc;

use crate::cover::{self, Stream};
use crate::relay;
use crate::server::Server;

/// Сколько датаграмм ждёт канала, прежде чем лишние теряются.
const DATAGRAM_QUEUE: usize = 256;

type Resolver = RequestResolver<h3_quinn::Connection, Bytes>;

/// Общее для всех запросов соединения.
struct State {
    server: Arc<Server>,
    quic: quinn::Connection,
    peer: SocketAddr,
    exporter: [u8; KEY_LEN],
    /// Имя опознанного пользователя.
    user: OnceLock<String>,
    /// Каналы датаграмм по номеру потока.
    routes: Mutex<HashMap<u64, mpsc::Sender<Bytes>>>,
}

/// Обслуживает соединение до его конца.
pub(crate) async fn serve(server: Arc<Server>, incoming: quinn::Incoming) {
    let peer = incoming.remote_address();
    let quic = match incoming.await {
        Ok(quic) => quic,
        Err(err) => {
            tracing::debug!(%peer, %err, "рукопожатие QUIC не состоялось");
            return;
        }
    };
    let mut exporter = [0u8; KEY_LEN];
    if quic
        .export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .is_err()
    {
        tracing::warn!(%peer, "экспорт ключей TLS не удался");
        return;
    }

    let built = h3::server::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .build::<_, Bytes>(h3_quinn::Connection::new(quic.clone()))
        .await;
    let mut h3 = match built {
        Ok(h3) => h3,
        Err(err) => {
            tracing::debug!(%peer, %err, "HTTP/3 не поднялся");
            return;
        }
    };

    let state = Arc::new(State {
        server,
        quic,
        peer,
        exporter,
        user: OnceLock::new(),
        routes: Mutex::default(),
    });
    let datagrams = tokio::spawn(route_datagrams(Arc::clone(&state)));
    loop {
        match h3.accept().await {
            Ok(Some(resolver)) => {
                tokio::spawn(handle(Arc::clone(&state), resolver));
            }
            Ok(None) => break,
            Err(err) => {
                tracing::debug!(%peer, %err, "соединение закрылось");
                break;
            }
        }
    }
    datagrams.abort();
}

async fn handle(state: Arc<State>, resolver: Resolver) {
    let (request, stream) = match resolver.resolve_request().await {
        Ok(resolved) => resolved,
        Err(err) => {
            tracing::trace!(peer = %state.peer, %err, "запрос не разобрался");
            return;
        }
    };
    if let Some(proof) = admit(&state, &request) {
        accept(stream, &proof).await;
        return;
    }
    let cover = state.server.config.cover.as_deref();
    if state.user.get().is_none() || request.method() != Method::CONNECT {
        cover::serve(cover, &request, stream).await;
        return;
    }
    let protocol = request.extensions().get::<h3::ext::Protocol>();
    match (protocol, request.uri().authority()) {
        (None, Some(authority)) => relay::stream(authority.as_str(), stream).await,
        (Some(&h3::ext::Protocol::CONNECT_UDP), _) if request.uri().path() == udp::PATH => {
            let (_route, incoming) = state.register(stream.id().into_inner());
            relay::datagram(stream, state.quic.clone(), incoming).await;
        }
        _ => cover::serve(cover, &request, stream).await,
    }
}

/// Проверяет опознание; `Some` — значение `pingwin-proof`.
fn admit(state: &State, request: &Request<()>) -> Option<String> {
    if request.method() != Method::GET || request.uri().path() != auth::PATH {
        return None;
    }
    let header = request
        .headers()
        .get(http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let policy = &state.server.policy;
    let admitted = auth::verify(header, &state.exporter, &state.server.keys, |user| {
        policy.password(user)
    })?;
    let name = policy.name(&admitted.user).unwrap_or("?");
    if state.user.set(name.to_owned()).is_ok() {
        tracing::info!(peer = %state.peer, user = name, "клиент опознан");
    }
    Some(admitted.proof)
}

async fn accept(mut stream: Stream, proof: &str) {
    let response = Response::builder()
        .status(StatusCode::from_u16(auth::ACCEPTED).unwrap_or(StatusCode::NO_CONTENT))
        .header(auth::PROOF_HEADER, proof)
        .body(());
    let Ok(response) = response else {
        return;
    };
    let sent = async {
        stream.send_response(response).await?;
        stream.finish().await
    };
    if let Err(err) = sent.await {
        tracing::debug!(%err, "ответ на опознание не ушёл");
    }
}

/// Раздаёт датаграммы соединения по каналам.
async fn route_datagrams(state: Arc<State>) {
    while let Ok(datagram) = state.quic.read_datagram().await {
        let Ok((stream_id, payload)) = udp::datagram::decode(datagram) else {
            continue;
        };
        if let Some(tx) = state.lock_routes().get(&stream_id) {
            let _ = tx.try_send(payload);
        }
    }
}

impl State {
    /// Заводит очередь датаграмм потока; она забывается вместе со сторожем.
    fn register(self: &Arc<Self>, stream_id: u64) -> (RouteGuard, mpsc::Receiver<Bytes>) {
        let (tx, rx) = mpsc::channel(DATAGRAM_QUEUE);
        self.lock_routes().insert(stream_id, tx);
        let guard = RouteGuard {
            state: Arc::clone(self),
            stream_id,
        };
        (guard, rx)
    }

    fn lock_routes(&self) -> std::sync::MutexGuard<'_, HashMap<u64, mpsc::Sender<Bytes>>> {
        self.routes.lock().unwrap_or_else(|e| e.into_inner())
    }
}

struct RouteGuard {
    state: Arc<State>,
    stream_id: u64,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        self.state.lock_routes().remove(&self.stream_id);
    }
}
