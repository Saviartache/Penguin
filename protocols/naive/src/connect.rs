//! Запрос `CONNECT` и разбор ответа сервера — общее для HTTP/2 и HTTP/3.
//!
//! И `h2`, и `h3` принимают один и тот же тип запроса — `http::Request<()>`,
//! — и отвечают одним и тем же `http::Response`. Собирать его дважды, по
//! разу на транспорт, означало бы держать в двух местах один и тот же список
//! заголовков.
//!
//! # Чего в запросе нет
//!
//! Ни `:scheme`, ни `:path` — `CONNECT` их не несёт вовсе (RFC 9113, §8.5):
//! `:authority` называет адрес назначения, и этого достаточно. Библиотеки
//! `h2` и `h3` берут это из `http::Uri`, разобранного в форме `host:port` —
//! без схемы и пути, то есть ровно как его строит [`request`].

use penguin_core::address::SocketAddress;
use penguin_transport::deadline;

use crate::basic;
use crate::error::{NaiveError, NaiveResult};
use crate::padding;

/// Собирает запрос `CONNECT`.
///
/// Заголовки дополнения уходят всегда, независимо от того, поддержит их
/// сервер или нет, — так делает и эталон (см. [`crate::padding`]).
pub fn request(
    target: &SocketAddress,
    credentials: Option<(&str, &str)>,
) -> NaiveResult<http::Request<()>> {
    let mut builder = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(target.to_wire());

    if let Some((username, password)) = credentials {
        builder = builder.header(
            http::header::PROXY_AUTHORIZATION,
            basic::header_value(username, password),
        );
    }
    for (name, value) in padding::request_headers() {
        builder = builder.header(name, value);
    }

    builder
        .body(())
        .map_err(|e| NaiveError::malformed(format!("запрос CONNECT не собирается: {e}")))
}

/// Ошибка, соответствующая коду ответа.
///
/// `None` — сервер согласился. У HTTP/2 и HTTP/3 нет строки причины, как у
/// HTTP/1.1, — только код, поэтому в тексте ошибки меньше подробностей, чем
/// у `http-proxy`.
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
