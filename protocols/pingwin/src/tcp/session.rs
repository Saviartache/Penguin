//! Соединение по TCP: TLS 1.3, HTTP/2 и то же опознание, что у HTTP/3.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::client::SendRequest;
use h2::{Ping, PingPong};
use http::{Method, Request, header};
use penguin_core::address::SocketAddress;
use penguin_proto::dialer::Dialer;
use penguin_transport::deadline;
use penguin_transport::tls::{ALPN_H2, TlsClient};
use tokio::task::JoinHandle;

use crate::connection::Target;
use crate::error::{PingwinError, PingwinResult};
use crate::stream::{self, PingwinStream};
use crate::tcp::datagram::TcpDatagram;
use crate::tcp::io::{H2Recv, H2Send};
use crate::wire::auth::{self, ClientAuth};
use crate::wire::keys::{EXPORTER_LABEL, KEY_LEN};
use crate::wire::{tcp, udp};

/// Как часто проверять, что сервер на месте: у TCP мёртвое соединение молчит.
const KEEPALIVE: Duration = Duration::from_secs(15);

/// Сколько ждать ответа на пинг.
const PING_LIMIT: Duration = Duration::from_secs(10);

/// Оборот ещё не измерен.
const UNKNOWN: u64 = u64::MAX;

/// Опознанное соединение HTTP/2.
pub(crate) struct Session {
    send: SendRequest<Bytes>,
    /// Качает кадры и пингует; кончилась — кончилось соединение.
    driver: JoinHandle<()>,
    /// Последний оборот пинга, микросекунды.
    rtt: Arc<AtomicU64>,
    authority: String,
}

impl Session {
    /// Поднимает TCP, TLS и HTTP/2 и проходит опознание.
    pub(crate) async fn establish(target: &Target, dialer: &dyn Dialer) -> PingwinResult<Self> {
        let tcp = penguin_proto::connect::dial(dialer, &target.host, target.port)
            .await
            .map_err(|e| PingwinError::disconnected(e.to_string()))?;
        tcp.set_nodelay(true)?;
        let io = TlsClient::new(&target.tls, &target.host, &[ALPN_H2])?
            .connect(tcp)
            .await?;

        let (_, tls) = io.get_ref();
        if tls.alpn_protocol() != Some(ALPN_H2) {
            return Err(PingwinError::malformed("сервер не согласился на HTTP/2"));
        }
        let mut exporter = [0u8; KEY_LEN];
        tls.export_keying_material(&mut exporter, EXPORTER_LABEL, Some(b""))
            .map_err(|_| PingwinError::malformed("экспорт ключей TLS не удался"))?;

        let (send, mut connection) = deadline::handshake("рукопожатие HTTP/2", async {
            h2::client::Builder::new()
                .enable_push(false)
                .initial_window_size(tcp::STREAM_WINDOW)
                .initial_connection_window_size(tcp::CONNECTION_WINDOW)
                .header_table_size(tcp::HEADER_TABLE)
                .max_header_list_size(tcp::MAX_HEADER_LIST)
                .max_send_buffer_size(tcp::SEND_BUFFER)
                .handshake::<_, Bytes>(io)
                .await
                .map_err(PingwinError::from)
        })
        .await?;
        let ping = connection
            .ping_pong()
            .ok_or_else(|| PingwinError::malformed("пинг HTTP/2 уже занят"))?;

        let rtt = Arc::new(AtomicU64::new(UNKNOWN));
        let measured = Arc::clone(&rtt);
        let driver = tokio::spawn(async move {
            tokio::select! {
                done = connection => if let Err(err) = done {
                    tracing::debug!(%err, "соединение HTTP/2 завершено");
                },
                () = keepalive(ping, &measured) => tracing::debug!("сервер не ответил на пинг"),
            }
        });

        let session = Self {
            send,
            driver,
            rtt,
            authority: target.server_name.clone(),
        };
        if let Err(err) =
            deadline::handshake("опознание pingwin", session.authenticate(&exporter, target)).await
        {
            session.close();
            return Err(err);
        }
        Ok(session)
    }

    async fn authenticate(&self, exporter: &[u8; KEY_LEN], target: &Target) -> PingwinResult<()> {
        let auth = ClientAuth::new(exporter, &target.server_public, &target.password)?;
        let request = Request::get(self.url(auth::PATH))
            .header(header::AUTHORIZATION, &auth.header)
            .body(())
            .map_err(|e| PingwinError::malformed(format!("запрос не собирается: {e}")))?;
        let (response, _) = self.ready().await?.send_request(request, true)?;
        let response = response.await?;
        let proof = response
            .headers()
            .get(auth::PROOF_HEADER)
            .and_then(|value| value.to_str().ok());
        if !auth.accepts(response.status().as_u16(), proof) {
            return Err(PingwinError::Rejected);
        }
        Ok(())
    }

    fn url(&self, path: &str) -> String {
        format!("https://{}{path}", self.authority)
    }

    async fn ready(&self) -> PingwinResult<SendRequest<Bytes>> {
        Ok(self.send.clone().ready().await?)
    }

    /// Соединение живо.
    pub(crate) fn is_alive(&self) -> bool {
        !self.driver.is_finished()
    }

    /// Открывает поток до `target`, не дожидаясь ответа сервера.
    pub(crate) async fn open_tcp(
        &self,
        target: &SocketAddress,
    ) -> PingwinResult<PingwinStream<H2Send, H2Recv>> {
        let authority = target.to_wire();
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(authority.as_str())
            .body(())
            .map_err(|e| PingwinError::malformed(format!("CONNECT к `{authority}`: {e}")))?;
        let (response, send) = self.ready().await?.send_request(request, false)?;
        Ok(PingwinStream::new(H2Send(send), async move {
            let response = response.await?;
            let status = response.status().as_u16();
            let mut recv = H2Recv::new(response.into_body());
            stream::confirm(status, &mut recv, authority).await?;
            Ok(recv)
        }))
    }

    /// Открывает датаграммный канал (капсулы в потоке); ждёт согласия сервера.
    pub(crate) async fn open_udp(&self) -> PingwinResult<TcpDatagram> {
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(self.url(udp::PATH))
            .header("capsule-protocol", "?1")
            .body(())
            .map_err(|e| PingwinError::malformed(format!("запрос канала: {e}")))?;
        request
            .extensions_mut()
            .insert(h2::ext::Protocol::from_static(udp::PROTOCOL));
        let (response, send) = self.ready().await?.send_request(request, false)?;
        let response = response.await?;
        let status = response.status();
        if status != http::StatusCode::OK {
            return Err(PingwinError::malformed(format!(
                "сервер не открыл датаграммный канал: ответ {status}"
            )));
        }
        Ok(TcpDatagram::new(send, H2Recv::new(response.into_body())))
    }

    /// Оборот по последнему пингу.
    pub(crate) fn rtt(&self) -> Option<Duration> {
        match self.rtt.load(Ordering::Relaxed) {
            UNKNOWN => None,
            micros => Some(Duration::from_micros(micros)),
        }
    }

    /// Закрывает соединение: задача держит TLS, с ней уходит и сокет.
    pub(crate) fn close(&self) {
        self.driver.abort();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// Пингует, пока сервер отвечает; запоминает оборот.
async fn keepalive(mut ping: PingPong, rtt: &AtomicU64) {
    loop {
        let started = Instant::now();
        match tokio::time::timeout(PING_LIMIT, ping.ping(Ping::opaque())).await {
            Ok(Ok(_pong)) => {
                let micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(UNKNOWN - 1);
                rtt.store(micros, Ordering::Relaxed);
            }
            Ok(Err(err)) => {
                tracing::debug!(%err, "пинг HTTP/2 не прошёл");
                return;
            }
            Err(_elapsed) => return,
        }
        tokio::time::sleep(KEEPALIVE).await;
    }
}
