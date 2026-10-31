//! Открытие потока gRPC `Tun` поверх готового соединения: свой HTTP/2 на каждый поток.

use http::{Method, Request};
use tokio::io::{AsyncRead, AsyncWrite};

use super::path::tun_path;
use super::stream::GrpcStream;
use crate::browser::CHROME_USER_AGENT;
use crate::error::{TransportError, TransportResult};
use crate::h2::{self, H2Stream};

/// Поток gRPC поверх HTTP/2.
pub type Grpc = GrpcStream<H2Stream>;

/// Открывает поток `Tun` службы `service_name` поверх `io`.
///
/// Ответа не ждёт: Xray шлёт заголовки вместе с первыми данными; ответ ждёт первое чтение.
pub async fn connect<S>(io: S, authority: &str, service_name: &str) -> TransportResult<Grpc>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut send_request = h2::handshake(io).await?;
    let request = request(authority, service_name)?;
    let (response, send) = send_request
        .send_request(request, false)
        .map_err(|e| TransportError::disconnected(format!("запрос gRPC: {e}")))?;
    Ok(GrpcStream::new(H2Stream::awaiting(send, response)))
}

/// Запрос `POST` к потоку `Tun`.
///
/// `:scheme` — `http`, как у Xray (grpc-go поверх своего диалера).
fn request(authority: &str, service_name: &str) -> TransportResult<Request<()>> {
    Request::builder()
        .method(Method::POST)
        .uri(format!("http://{authority}{}", tun_path(service_name)))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("user-agent", CHROME_USER_AGENT)
        .body(())
        .map_err(|e| TransportError::config(format!("запрос gRPC: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_is_a_grpc_call() {
        let request = request("example.com", "svc").expect("собирается");
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri().path(), "/svc/Tun");
        assert_eq!(
            request.uri().authority().map(|a| a.as_str()),
            Some("example.com")
        );
        assert_eq!(request.headers()["content-type"], "application/grpc");
        assert_eq!(request.headers()["te"], "trailers");
    }

    #[test]
    fn a_broken_authority_is_a_config_error() {
        assert!(matches!(
            request("bad host", "svc"),
            Err(TransportError::Config(_))
        ));
    }
}
