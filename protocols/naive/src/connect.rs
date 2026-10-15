//! Запрос `CONNECT` и разбор ответа сервера — общее для HTTP/2 и HTTP/3.
//!
//! Список заголовков один; собирается он в запрос `h2` или
//! HTTP/3 — разница только в типе.
//!
//! # Чего в запросе нет
//!
//! Ни `:scheme`, ни `:path` — `CONNECT` их не несёт вовсе (RFC 9113, §8.5;
//! RFC 9114, §4.4): `:authority` называет адрес назначения, и этого
//! достаточно. `h2` берёт его из `http::Uri` в форме `host:port`, HTTP/3 —
//! из [`penguin_transport::h3::Request::connect`].

use penguin_core::address::SocketAddress;
use penguin_transport::deadline;
use penguin_transport::h3;

use crate::basic;
use crate::error::{NaiveError, NaiveResult};
use crate::padding;

/// Заголовки `CONNECT`: пароль, если он есть, и дополнение.
///
/// Заголовки дополнения уходят всегда, независимо от того, поддержит их
/// сервер или нет, — так делает и эталон (см. [`crate::padding`]).
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

/// Ошибка, соответствующая коду ответа.
///
/// `None` — сервер согласился. У HTTP/2 и HTTP/3 нет строки причины — только
/// код.
pub fn outcome(status: u16, target: &str) -> Option<NaiveError> {
    match status {
        200..=299 => None,
        // 407 — «нужен пароль», 401 шлют те, кто путает его с обычным.
        401 | 407 => Some(NaiveError::AuthRejected { status }),
        _ => Some(NaiveError::Refused {
            target: target.to_owned(),
            status,
        }),
    }
}

/// Открывает тоннель через сервер: срок на рукопожатие плюс проверка ответа.
///
/// `open` — то, что у HTTP/2 и HTTP/3 устроено по-разному: отправка запроса и
/// получение потока для тела. Здесь остаётся общее — срок и разбор кода.
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
        // RFC 9113, §8.5: `CONNECT` не несёт ни того, ни другого.
        let request = request(&target(), None).expect("собирается");
        assert_eq!(request.method(), http::Method::CONNECT);
        assert!(request.uri().scheme().is_none());
        // Форма `host:port` без пути: `http::Uri` в этом случае отдаёт
        // пустую строку, а не `/` — заголовок `CONNECT` его и не несёт.
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
        // RFC 9114, §4.4 — ровно то, чего не умел `h3` 0.0.8.
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
        // Эталон шлёт их независимо от того, поддержит сервер схему или нет.
        let request = request(&target(), None).expect("собирается");
        assert!(request.headers().contains_key(padding::HEADER_PADDING));
        assert_eq!(request.headers()[padding::HEADER_TYPE_REQUEST], "1");
    }

    #[test]
    fn a_name_stays_a_name_in_the_request() {
        // Разрешить его здесь значило бы отдать серверу адрес из CDN вместо
        // имени, по которому написано правило.
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
        // От этого зависит, будет ли `supervisor` повторять попытку.
        let err = outcome(407, "example.com:443").expect("отказ");
        assert!(matches!(err, NaiveError::AuthRejected { .. }));

        let err = outcome(502, "example.com:443").expect("отказ");
        assert!(matches!(err, NaiveError::Refused { .. }));

        assert!(outcome(200, "example.com:443").is_none());
        // Сервер вправе ответить любым 2xx.
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
