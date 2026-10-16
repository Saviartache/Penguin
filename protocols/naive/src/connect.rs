//! Запрос `CONNECT` и разбор ответа сервера — общее для HTTP/2 и HTTP/3.
//!
//! Без `:scheme` и `:path` (RFC 9113, §8.5; RFC 9114, §4.4): адрес назначения
//! — только в `:authority`.

use penguin_core::address::SocketAddress;
use penguin_transport::deadline;
use penguin_transport::h3;

use crate::basic;
use crate::error::{NaiveError, NaiveResult};
use crate::padding;

/// Заголовки `CONNECT`: пароль (если есть) и дополнение, которое уходит всегда.
fn headers(credentials: Option<(&str, &str)>) -> Vec<(&'static str, String)> {
    let mut headers = Vec::with_capacity(3);
    if let Some((username, password)) = credentials {
        headers.push((
            http::header::PROXY_AUTHORIZATION.as_str(),
            basic::header_value(username, password),
        ));
    }
    headers.extend(padding::request_headers());
    headers
}

/// Собирает запрос `CONNECT` для HTTP/2.
pub fn request(
    target: &SocketAddress,
    credentials: Option<(&str, &str)>,
) -> NaiveResult<http::Request<()>> {
    let mut builder = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(target.to_wire());
    for (name, value) in headers(credentials) {
        builder = builder.header(name, value);
    }
    builder
        .body(())
        .map_err(|e| NaiveError::malformed(format!("запрос CONNECT не собирается: {e}")))
}

/// Собирает запрос `CONNECT` для HTTP/3.
pub fn request_h3(target: &SocketAddress, credentials: Option<(&str, &str)>) -> h3::Request {
    headers(credentials).into_iter().fold(
        h3::Request::connect(target.to_wire()),
        |request, (name, value)| request.header(name, value),
    )
}

/// Ошибка по коду ответа; `None` — сервер согласился.
pub fn outcome(status: u16, target: &str) -> Option<NaiveError> {
    match status {
        200..=299 => None,
        401 | 407 => Some(NaiveError::AuthRejected { status }),
        _ => Some(NaiveError::Refused {
            target: target.to_owned(),
            status,
        }),
    }
}

/// Открывает тоннель: срок на рукопожатие и проверка кода; `open` отправляет запрос.
pub async fn perform<S, F>(target: &SocketAddress, open: F) -> NaiveResult<S>
where
    F: std::future::Future<Output = NaiveResult<(u16, S)>>,
{
    deadline::handshake("ответ сервера на CONNECT", async {
        let (status, stream) = open.await?;
        match outcome(status, &target.to_wire()) {
            Some(err) => Err(err),
            None => Ok(stream),
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> SocketAddress {
        SocketAddress::domain("example.com", 443)
    }

    #[test]
    fn the_request_has_no_scheme_or_path() {
        let request = request(&target(), None).expect("собирается");
        assert_eq!(request.method(), http::Method::CONNECT);
        assert!(request.uri().scheme().is_none());
        assert_eq!(request.uri().path(), "");
        assert_eq!(
            request
                .uri()
                .authority()
                .map(ToString::to_string)
                .as_deref(),
            Some("example.com:443")
        );
    }

    #[test]
    fn the_http3_request_has_no_scheme_or_path_either() {
        use penguin_transport::h3::qpack::field;

        let block = request_h3(&target(), Some(("Aladdin", "open sesame"))).encode();
        let fields = field::decode(&block, usize::MAX).expect("разбирается");
        let names: Vec<&[u8]> = fields.iter().map(|f| f.name.as_slice()).collect();
        assert_eq!(names[..2], [&b":method"[..], b":authority"]);
        assert!(!names.contains(&&b":scheme"[..]));
        assert!(!names.contains(&&b":path"[..]));
        assert_eq!(fields[1].value, b"example.com:443");
        assert!(names.contains(&&b"proxy-authorization"[..]));
        assert!(names.contains(&padding::HEADER_PADDING.as_bytes()));
    }

    #[test]
    fn credentials_go_into_the_header() {
        let request = request(&target(), Some(("Aladdin", "open sesame"))).expect("собирается");
        assert_eq!(
            request.headers()[http::header::PROXY_AUTHORIZATION],
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    #[test]
    fn padding_headers_are_always_attached() {
        let request = request(&target(), None).expect("собирается");
        assert!(request.headers().contains_key(padding::HEADER_PADDING));
        assert_eq!(request.headers()[padding::HEADER_TYPE_REQUEST], "1");
    }

    #[test]
    fn a_name_stays_a_name_in_the_request() {
        let request =
            request(&SocketAddress::domain("youtube.com", 443), None).expect("собирается");
        assert_eq!(
            request
                .uri()
                .authority()
                .map(ToString::to_string)
                .as_deref(),
            Some("youtube.com:443")
        );
    }

    #[test]
    fn a_wrong_password_is_told_apart_from_a_refusal() {
        let err = outcome(407, "example.com:443").expect("отказ");
        assert!(matches!(err, NaiveError::AuthRejected { .. }));

        let err = outcome(502, "example.com:443").expect("отказ");
        assert!(matches!(err, NaiveError::Refused { .. }));

        assert!(outcome(200, "example.com:443").is_none());
        assert!(outcome(201, "example.com:443").is_none());
    }

    #[tokio::test]
    async fn a_tunnel_opens_when_the_status_is_good() {
        let (client, _server) = tokio::io::duplex(64);
        let stream = perform(&target(), async { Ok((200, client)) })
            .await
            .expect("сервер согласился");
        drop(stream);
    }

    #[tokio::test]
    async fn a_refusal_names_the_target() {
        let (client, _server) = tokio::io::duplex(64);
        let err = perform(&target(), async { Ok((403, client)) })
            .await
            .expect_err("сервер отказал");
        assert!(err.to_string().contains("example.com:443"));
    }
}
