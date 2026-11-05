//! XHTTP `stream-one` по HTTP/2 поверх готового соединения.
//!
//! Так Xray ходит поверх Reality (`decideHTTPVersion`: при Reality — `2`); сервер
//! принимает HTTP/2 без ALPN (`h2c.NewHandler` в `hub.go`). Потоки делят одно
//! соединение ([`Pool`]), как XMUX Xray без настроек (`mux.go`: одно соединение,
//! новое — когда старое закрылось): рукопожатие на поток сервер не выдерживает.

use std::future::Future;

use ::h2::client::SendRequest;
use bytes::Bytes;
use http::{Method, Request};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use super::request::parts;
use crate::error::{TransportError, TransportResult};
use crate::h2::{self, H2Stream};

/// Открывает поток `stream-one` поверх `io`; ответ ждёт первое чтение.
pub async fn connect<S>(io: S, authority: &str, path: &str) -> TransportResult<H2Stream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let send_request = h2::handshake(io).await?;
    open(send_request, authority, path).map(|(_, stream)| stream)
}

/// Общее соединение HTTP/2 для потоков `stream-one` к одному серверу.
#[derive(Debug, Default)]
pub struct Pool {
    current: Mutex<Option<SendRequest<Bytes>>>,
}

impl Pool {
    /// Открывает поток по живому соединению; нет его — поднимает через `connect`.
    /// Подъём идёт под замком: ждущие потоки не множат рукопожатия.
    pub async fn open<S, E, F, Fut>(
        &self,
        authority: &str,
        path: &str,
        connect: F,
    ) -> Result<H2Stream, E>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        E: From<TransportError>,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<S, E>>,
    {
        let mut current = self.current.lock().await;
        let alive = match current.take() {
            // Закрытое соединение отвечает ошибкой, а не ждёт.
            Some(send_request) => send_request.ready().await.ok(),
            None => None,
        };
        let send_request = match alive {
            Some(send_request) => send_request,
            None => h2::handshake(connect().await?).await?,
        };
        let (send_request, stream) = open(send_request, authority, path)?;
        *current = Some(send_request);
        Ok(stream)
    }

    /// Забывает соединение: оно закроется с последним потоком.
    pub async fn close(&self) {
        self.current.lock().await.take();
    }
}

/// Шлёт запрос `stream-one`; соединение возвращается для следующих потоков.
fn open(
    mut send_request: SendRequest<Bytes>,
    authority: &str,
    path: &str,
) -> TransportResult<(SendRequest<Bytes>, H2Stream)> {
    let (response, send) = send_request
        .send_request(request(authority, path)?, false)
        .map_err(|e| TransportError::disconnected(format!("запрос XHTTP: {e}")))?;
    Ok((send_request, H2Stream::awaiting(send, response)))
}

/// Запрос `POST` с заголовками `stream-one`.
fn request(authority: &str, path: &str) -> TransportResult<Request<()>> {
    let (target, headers) = parts(authority, path);
    headers
        .into_iter()
        .fold(
            Request::builder()
                .method(Method::POST)
                .uri(format!("https://{authority}{target}")),
            |builder, (name, value)| builder.header(name, value),
        )
        .body(())
        .map_err(|e| TransportError::config(format!("запрос XHTTP: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_is_a_stream_one_post() {
        let request = request("www.heise.de", "/security").expect("собирается");
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri().path(), "/security/");
        assert_eq!(
            request.uri().authority().map(|a| a.as_str()),
            Some("www.heise.de")
        );
        assert_eq!(request.headers()["content-type"], "application/grpc");
        assert!(request.headers().contains_key("referer"));
    }

    #[test]
    fn a_broken_authority_is_a_config_error() {
        assert!(matches!(
            request("bad host", "/"),
            Err(TransportError::Config(_))
        ));
    }

    /// Сервер HTTP/2: принимает `limit` запросов и рвёт соединение.
    fn server(
        io: tokio::io::DuplexStream,
        accepted: tokio::sync::mpsc::UnboundedSender<()>,
        limit: usize,
    ) {
        tokio::spawn(async move {
            let Ok(mut connection) = ::h2::server::handshake(io).await else {
                return;
            };
            for _ in 0..limit {
                let Some(Ok(_request)) = connection.accept().await else {
                    return;
                };
                let _ = accepted.send(());
            }
        });
    }

    #[tokio::test]
    async fn streams_share_one_connection_until_it_closes() {
        let pool = Pool::default();
        let (accepted, mut requests) = tokio::sync::mpsc::unbounded_channel();
        let dials = std::sync::atomic::AtomicUsize::new(0);
        let dial = || {
            dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let (client, peer) = tokio::io::duplex(64 * 1024);
            server(peer, accepted.clone(), 2);
            async move { Ok::<_, TransportError>(client) }
        };

        let _first = pool.open("a.example", "/p", &dial).await.expect("поток");
        let _second = pool.open("a.example", "/p", &dial).await.expect("поток");
        requests.recv().await.expect("первый запрос");
        requests.recv().await.expect("второй запрос");
        assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 1);

        // Сервер порвал соединение — следующий поток поднимает новое.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _third = pool.open("a.example", "/p", &dial).await.expect("поток");
        requests.recv().await.expect("третий запрос");
        assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 2);
    }
}
