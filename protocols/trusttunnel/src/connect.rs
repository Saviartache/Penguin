//! Запрос `CONNECT` и разбор ответа сервера — общее для адреса назначения и
//! псевдо-хостов.
//!
//! # Чего в запросе нет
//!
//! Ни `:scheme`, ни `:path` — `CONNECT` их не несёт вовсе (RFC 9113, §8.5;
//! `PROTOCOL.md`, §5.1 приводит только `:method` и `:authority`).
//! `http::Uri`, разобранный из строки вида `host:port` или из голого имени
//! без порта (`_udp2`, `_check`), даёт ровно такую форму: `h2` берёт из неё
//! `:authority`, а `:scheme`/`:path` остаются пустыми.
//!
//! # Заголовок `user-agent`
//!
//! Спецификация (§5.1) помечает его обязательным и предписывает форму
//! `<platform> <app_name>`. У сервера-эталона это поле — только метка для
//! метрик (`lib/src/http_downstream.rs::user_agent`, ревизия сверки ниже):
//! оно не участвует ни в маршрутизации, ни в опознании. Платформу и имя
//! приложения этот крейт не знает и знать не может — `protocols/*` не видит
//! ничего выше [`penguin_core`] (`AGENTS.md`, §1.1), а имя конкретного
//! приложения на потоке архитектура клиента протоколу и вовсе не передаёт.
//! Поэтому здесь стоит общая константа, а не разобранная по спецификации
//! пара — это осознанное упрощение, а не пропуск.

use std::future::Future;

use penguin_core::address::SocketAddress;
use penguin_transport::deadline;

use crate::basic;
use crate::error::{TrustTunnelError, TrustTunnelResult};

/// Псевдо-хост UDP-мультиплексора (`PROTOCOL.md`, §6.2, приложение A).
pub const UDP_AUTHORITY: &str = "_udp2";

/// Псевдо-хост проверки живости (`PROTOCOL.md`, §8.2, приложение A).
pub const HEALTH_CHECK_AUTHORITY: &str = "_check";

/// Значение заголовка `user-agent`. См. пояснение в шапке модуля.
const USER_AGENT: &str = "penguin";

/// Собирает запрос `CONNECT` до обычного адреса назначения.
pub fn request(
    target: &SocketAddress,
    credentials: (&str, &str),
) -> TrustTunnelResult<http::Request<()>> {
    build(&target.to_wire(), credentials)
}

/// Собирает запрос `CONNECT` до псевдо-хоста: [`UDP_AUTHORITY`] или
/// [`HEALTH_CHECK_AUTHORITY`].
pub fn request_pseudo(
    authority: &str,
    credentials: (&str, &str),
) -> TrustTunnelResult<http::Request<()>> {
    build(authority, credentials)
}

fn build(authority: &str, credentials: (&str, &str)) -> TrustTunnelResult<http::Request<()>> {
    let (username, password) = credentials;
    http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(authority)
        .header(http::header::USER_AGENT, USER_AGENT)
        .header(
            http::header::PROXY_AUTHORIZATION,
            basic::header_value(username, password),
        )
        .body(())
        .map_err(|e| TrustTunnelError::malformed(format!("запрос CONNECT не собирается: {e}")))
}

/// Ошибка, соответствующая коду ответа.
///
/// `None` — сервер согласился. `407` — единственный код, который
/// спецификация называет по имени (§5.2, §9.2); всё остальное вне `2xx` —
/// отказ, не обязательно означающий неверный пароль.
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

/// Открывает тоннель через сервер: срок на рукопожатие плюс проверка ответа.
///
/// `open` отправляет запрос и возвращает код ответа вместе с потоком тела —
/// то, что у HTTP/2 своё для каждого вызывающего. Здесь остаётся общее: срок
/// и разбор кода.
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
        // RFC 9113, §8.5: `CONNECT` не несёт ни того, ни другого.
        let target = SocketAddress::domain("example.com", 443);
        let request = request(&target, creds()).expect("собирается");
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
        // `PROTOCOL.md`, приложение A: порт у `_udp2`/`_check` — не «любой»,
        // а отсутствует буквально; в заголовке `:authority` не должно
        // появиться `_udp2:0` — сервер сверяет authority строкой целиком
        // (`lib/src/http_downstream.rs`, `authority.as_str()`).
        for host in [UDP_AUTHORITY, HEALTH_CHECK_AUTHORITY] {
            let request = request_pseudo(host, creds()).expect("собирается");
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
        // `PROTOCOL.md`, §9.1: опознание уходит на каждом `CONNECT`, включая
        // псевдо-хосты, — не только на обычных адресах.
        for request in [
            request(&SocketAddress::domain("example.com", 443), creds()).expect("собирается"),
            request_pseudo(UDP_AUTHORITY, creds()).expect("собирается"),
            request_pseudo(HEALTH_CHECK_AUTHORITY, creds()).expect("собирается"),
        ] {
            assert_eq!(
                request.headers()[http::header::PROXY_AUTHORIZATION],
                "Basic cGVuZ3VpbjpzZWNyZXQ="
            );
        }
    }

    #[test]
    fn a_407_is_told_apart_from_a_plain_refusal() {
        // От этого зависит, пересоздаст ли `supervisor` всю сессию
        // (`PROTOCOL.md`, §9.2) или просто повторит попытку.
        let err = outcome(407, "example.com:443").expect("отказ");
        assert!(matches!(err, TrustTunnelError::AuthRejected { .. }));

        let err = outcome(502, "example.com:443").expect("отказ");
        assert!(matches!(err, TrustTunnelError::Refused { .. }));

        assert!(outcome(200, "example.com:443").is_none());
        // Сервер вправе ответить любым 2xx.
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
