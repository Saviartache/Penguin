//! Запрос `CONNECT` и разбор ответа — для адреса назначения и псевдо-хостов.
//!
//! Без `:scheme` и `:path` (RFC 9113, §8.5; RFC 9114, §4.4; `PROTOCOL.md`, §5.1).
//! `user-agent` (§5.1 велит `<platform> <app_name>`) — константа: у эталона
//! это метка метрик (`lib/src/http_downstream.rs::user_agent`), а платформу и
//! приложение протокол не видит (`AGENTS.md`, §1.1).

use std::future::Future;

use penguin_transport::{deadline, h3};

use crate::basic;
use crate::error::{TrustTunnelError, TrustTunnelResult};

/// Псевдо-хост UDP-мультиплексора (`PROTOCOL.md`, §6.2, приложение A).
pub const UDP_AUTHORITY: &str = "_udp2";

/// Псевдо-хост проверки живости (`PROTOCOL.md`, §8.2, приложение A).
pub const HEALTH_CHECK_AUTHORITY: &str = "_check";

/// Значение `user-agent`.
const USER_AGENT: &str = "penguin";

/// Заголовки `CONNECT` — одни и те же у HTTP/2 и HTTP/3.
fn headers(credentials: (&str, &str)) -> [(&'static str, String); 2] {
    let (username, password) = credentials;
    [
        (http::header::USER_AGENT.as_str(), USER_AGENT.to_owned()),
        (
            http::header::PROXY_AUTHORIZATION.as_str(),
            basic::header_value(username, password),
        ),
    ]
}

/// Запрос `CONNECT` для HTTP/2 до `authority` (адрес или [`UDP_AUTHORITY`], [`HEALTH_CHECK_AUTHORITY`]).
pub fn request(authority: &str, credentials: (&str, &str)) -> TrustTunnelResult<http::Request<()>> {
    let mut builder = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(authority);
    for (name, value) in headers(credentials) {
        builder = builder.header(name, value);
    }
    builder
        .body(())
        .map_err(|e| TrustTunnelError::malformed(format!("запрос CONNECT не собирается: {e}")))
}

/// Собирает запрос `CONNECT` для HTTP/3 до `authority`.
pub fn request_h3(authority: &str, credentials: (&str, &str)) -> h3::Request {
    headers(credentials)
        .into_iter()
        .fold(h3::Request::connect(authority), |request, (name, value)| {
            request.header(name, value)
        })
}

/// Ошибка по коду ответа; `None` — согласие. Только `407` — отказ опознания (§5.2, §9.2).
pub fn outcome(status: u16, target: &str) -> Option<TrustTunnelError> {
    match status {
        200..=299 => None,
        407 => Some(TrustTunnelError::AuthRejected { status }),
        _ => Some(TrustTunnelError::Refused {
            target: target.to_owned(),
            status,
        }),
    }
}

/// Открывает тоннель: срок и проверка кода; `open` отправляет запрос и отдаёт код с потоком.
pub async fn perform<S, F>(target: &str, open: F) -> TrustTunnelResult<S>
where
    F: Future<Output = TrustTunnelResult<(u16, S)>>,
{
    deadline::handshake("ответ сервера на CONNECT", async {
        let (status, stream) = open.await?;
        match outcome(status, target) {
            Some(err) => Err(err),
            None => Ok(stream),
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> (&'static str, &'static str) {
        ("penguin", "secret")
    }

    #[test]
    fn the_request_has_no_scheme_or_path() {
        let request = request("example.com:443", creds()).expect("собирается");
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
    fn a_pseudo_host_has_no_port_at_all() {
        for host in [UDP_AUTHORITY, HEALTH_CHECK_AUTHORITY] {
            let request = request(host, creds()).expect("собирается");
            assert_eq!(
                request
                    .uri()
                    .authority()
                    .map(ToString::to_string)
                    .as_deref(),
                Some(host)
            );
            assert!(request.uri().port_u16().is_none());
        }
    }

    #[test]
    fn credentials_go_into_the_header_on_every_request() {
        for authority in ["example.com:443", UDP_AUTHORITY, HEALTH_CHECK_AUTHORITY] {
            let request = request(authority, creds()).expect("собирается");
            assert_eq!(
                request.headers()[http::header::PROXY_AUTHORIZATION],
                "Basic cGVuZ3VpbjpzZWNyZXQ="
            );
        }
    }

    #[test]
    fn the_http3_request_carries_the_same_fields() {
        use penguin_transport::h3::qpack::field;

        let block = request_h3(UDP_AUTHORITY, creds()).encode();
        let fields: Vec<(Vec<u8>, Vec<u8>)> = field::decode(&block, usize::MAX)
            .expect("разбирается")
            .into_iter()
            .map(|f| (f.name, f.value))
            .collect();
        assert_eq!(
            fields,
            [
                (b":method".to_vec(), b"CONNECT".to_vec()),
                (b":authority".to_vec(), b"_udp2".to_vec()),
                (b"user-agent".to_vec(), b"penguin".to_vec()),
                (
                    b"proxy-authorization".to_vec(),
                    b"Basic cGVuZ3VpbjpzZWNyZXQ=".to_vec()
                ),
            ]
        );
    }

    #[test]
    fn a_407_is_told_apart_from_a_plain_refusal() {
        let err = outcome(407, "example.com:443").expect("отказ");
        assert!(matches!(err, TrustTunnelError::AuthRejected { .. }));

        let err = outcome(502, "example.com:443").expect("отказ");
        assert!(matches!(err, TrustTunnelError::Refused { .. }));

        assert!(outcome(200, "example.com:443").is_none());
        assert!(outcome(201, "example.com:443").is_none());
    }

    #[tokio::test]
    async fn a_tunnel_opens_when_the_status_is_good() {
        let (client, _server) = tokio::io::duplex(64);
        let stream = perform("example.com:443", async { Ok((200, client)) })
            .await
            .expect("сервер согласился");
        drop(stream);
    }

    #[tokio::test]
    async fn a_refusal_names_the_target() {
        let (client, _server) = tokio::io::duplex(64);
        let err = perform("example.com:443", async { Ok((403, client)) })
            .await
            .expect_err("сервер отказал");
        assert!(err.to_string().contains("example.com:443"));
    }
}
