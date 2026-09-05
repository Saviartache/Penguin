//! Запрос `CONNECT-UDP` и разбор ответа (RFC 9298, §2–3).
//!
//! # Шаблон URI
//!
//! RFC 9298, §2 не фиксирует путь запроса — прокси может слушать на любом,
//! и клиент обязан быть настроен шаблоном URI (RFC 6570). Этот крейт не даёт
//! такую настройку отдельным полем, а всегда берёт шаблон по умолчанию,
//! названный в самом RFC:
//!
//! ```text
//! https://$PROXY_HOST:$PROXY_PORT/.well-known/masque/udp/{target_host}/{target_port}/
//! ```
//!
//! Он существует ровно для клиентов вроде этого — «не желающих или не
//! способных поддержать произвольные шаблоны» (RFC 9298, §2) — и подходит
//! любому серверу, который сам следует умолчанию (среди них — `masquerade`,
//! эталонная реализация IETF). Собственный путь прокси в эту схему не ложится
//! никак: расширять настройки шаблоном — задача для того, кто столкнётся с
//! таким сервером на практике, а не заранее.
//!
//! # Кодирование `target_host`
//!
//! IPv6 без скобок, двоеточия закодированы `%3A` — ровно так, как того
//! требует RFC 9298, §2 (пример там же: `2001:db8::42` →
//! `2001%3Adb8%3A%3A42`). Домен и IPv4 почти всегда обходятся без замен, но
//! экранируются той же функцией — так домен с символом вне `unreserved`
//! (RFC 3986, §2.3) не ломает путь молча.

use h3::ext::Protocol;
use http::uri::Authority;
use penguin_core::address::{Address, SocketAddress};
use penguin_transport::deadline;

use crate::error::{MasqueError, MasqueResult};
use crate::transport::{H3BidiStream, H3SendRequest};

/// Значение заголовка, которым сервер подтверждает протокол капсул
/// (RFC 9297, §3.2; структурное булево «истина», RFC 8941, §3.3.6).
const CAPSULE_PROTOCOL_CONFIRMED: &str = "?1";

/// Собирает запрос `CONNECT-UDP` до `target` через прокси `authority`.
pub fn request(
    authority: &Authority,
    target: &SocketAddress,
    authorization: Option<&str>,
) -> MasqueResult<http::Request<()>> {
    let path = format!(
        "/.well-known/masque/udp/{}/{}/",
        encode_target_host(&target.host),
        target.port
    );

    let mut builder = http::Request::builder()
        .method(http::Method::CONNECT)
        .extension(Protocol::CONNECT_UDP)
        .uri(
            http::Uri::builder()
                .scheme("https")
                .authority(authority.clone())
                .path_and_query(path)
                .build()
                .map_err(|e| MasqueError::malformed(format!("URI CONNECT-UDP: {e}")))?,
        )
        .header("capsule-protocol", CAPSULE_PROTOCOL_CONFIRMED);

    if let Some(value) = authorization {
        builder = builder.header(http::header::AUTHORIZATION, value);
    }

    builder
        .body(())
        .map_err(|e| MasqueError::malformed(format!("запрос CONNECT-UDP не собирается: {e}")))
}

/// Кодирует `target_host` для подстановки в путь (RFC 9298, §2).
fn encode_target_host(host: &Address) -> String {
    match host {
        Address::Domain(domain) => percent_encode_path_segment(domain),
        Address::Ip(ip) => percent_encode_path_segment(&ip.to_string()),
    }
}

/// Процентное кодирование одного сегмента пути: всё, кроме `unreserved`
/// (RFC 3986, §2.3), заменяется на `%XX`.
fn percent_encode_path_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Ошибка, соответствующая коду ответа. `None` — сервер согласился.
fn outcome(status: u16, target: &str) -> Option<MasqueError> {
    match status {
        200..=299 => None,
        401 | 407 => Some(MasqueError::AuthRejected { status }),
        _ => Some(MasqueError::Refused {
            target: target.to_owned(),
            status,
        }),
    }
}

/// Проверяет, что успешный ответ действительно подтвердил протокол капсул.
///
/// Это отдельная проверка от [`outcome`]: `2xx` без `capsule-protocol: ?1` —
/// не отказ прокси, а нарушение формата (RFC 9298, §3.5), и `supervisor`
/// не должен путать его с обрывом сети.
fn confirms_capsule_protocol(headers: &http::HeaderMap) -> bool {
    headers
        .get("capsule-protocol")
        .and_then(|value| value.to_str().ok())
        == Some(CAPSULE_PROTOCOL_CONFIRMED)
}

/// Открывает поток `CONNECT-UDP`: срок на рукопожатие, разбор кода и
/// подтверждения протокола капсул.
pub async fn perform(
    target: &SocketAddress,
    mut send_request: H3SendRequest,
    request: http::Request<()>,
) -> MasqueResult<h3::client::RequestStream<H3BidiStream, bytes::Bytes>> {
    deadline::handshake("ответ прокси на CONNECT-UDP", async {
        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|e| MasqueError::Disconnected(e.to_string()))?;

        let response = stream
            .recv_response()
            .await
            .map_err(|e| MasqueError::Disconnected(e.to_string()))?;

        let status = response.status().as_u16();
        if let Some(err) = outcome(status, &target.to_wire()) {
            return Err(err);
        }
        if !confirms_capsule_protocol(response.headers()) {
            return Err(MasqueError::malformed(
                "успешный ответ без заголовка `capsule-protocol: ?1`",
            ));
        }

        Ok(stream)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> Authority {
        Authority::from_static("proxy.example.com:443")
    }

    fn target() -> SocketAddress {
        SocketAddress::domain("target.example.com", 53)
    }

    #[test]
    fn the_request_uses_extended_connect_with_the_connect_udp_protocol() {
        let request = request(&authority(), &target(), None).expect("собирается");
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(
            request.extensions().get::<Protocol>().copied(),
            Some(Protocol::CONNECT_UDP)
        );
        assert_eq!(request.headers()["capsule-protocol"], "?1");
    }

    #[test]
    fn the_path_carries_the_default_uri_template() {
        let request = request(&authority(), &target(), None).expect("собирается");
        assert_eq!(
            request.uri().path(),
            "/.well-known/masque/udp/target.example.com/53/"
        );
    }

    #[test]
    fn an_ipv6_target_has_its_colons_escaped() {
        // Пример из RFC 9298, §2: `2001:db8::42` → `2001%3Adb8%3A%3A42`.
        let target = SocketAddress::new(Address::Ip("2001:db8::42".parse().expect("адрес")), 443);
        let request = request(&authority(), &target, None).expect("собирается");
        assert_eq!(
            request.uri().path(),
            "/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/"
        );
    }

    #[test]
    fn authorization_is_attached_when_configured() {
        let request =
            request(&authority(), &target(), Some("Bearer секрет-токен")).expect("собирается");
        assert_eq!(
            request.headers()[http::header::AUTHORIZATION],
            "Bearer секрет-токен"
        );
    }

    #[test]
    fn no_authorization_header_without_configuration() {
        let request = request(&authority(), &target(), None).expect("собирается");
        assert!(!request.headers().contains_key(http::header::AUTHORIZATION));
    }

    #[test]
    fn a_wrong_credential_is_told_apart_from_a_refusal() {
        let err = outcome(407, "target.example.com:53").expect("отказ");
        assert!(matches!(err, MasqueError::AuthRejected { .. }));

        let err = outcome(502, "target.example.com:53").expect("отказ");
        assert!(matches!(err, MasqueError::Refused { .. }));

        assert!(outcome(200, "target.example.com:53").is_none());
        assert!(outcome(201, "target.example.com:53").is_none());
    }

    #[test]
    fn a_success_without_the_capsule_header_is_malformed_not_a_refusal() {
        let mut headers = http::HeaderMap::new();
        assert!(!confirms_capsule_protocol(&headers));

        headers.insert("capsule-protocol", http::HeaderValue::from_static("?0"));
        assert!(!confirms_capsule_protocol(&headers));

        headers.insert("capsule-protocol", http::HeaderValue::from_static("?1"));
        assert!(confirms_capsule_protocol(&headers));
    }
}
