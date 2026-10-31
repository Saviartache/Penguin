//! XHTTP `stream-one` по HTTP/2 поверх готового соединения: свой HTTP/2 на каждый поток.
//!
//! Так Xray ходит поверх Reality (`decideHTTPVersion`: при Reality — `2`); сервер
//! принимает HTTP/2 без ALPN (`h2c.NewHandler` в `hub.go`).

use http::{Method, Request};
use tokio::io::{AsyncRead, AsyncWrite};

use super::request::parts;
use crate::error::{TransportError, TransportResult};
use crate::h2::{self, H2Stream};

/// Открывает поток `stream-one` поверх `io`; ответ ждёт первое чтение.
pub async fn connect<S>(io: S, authority: &str, path: &str) -> TransportResult<H2Stream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut send_request = h2::handshake(io).await?;
    let (response, send) = send_request
        .send_request(request(authority, path)?, false)
        .map_err(|e| TransportError::disconnected(format!("запрос XHTTP: {e}")))?;
    Ok(H2Stream::awaiting(send, response))
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
}
