//! Запрос `CONNECT-UDP` и разбор ответа (RFC 9298, §2–3).
//!
//! Всегда шаблон по умолчанию (RFC 9298, §2):
//!
//! ```text
//! https://$PROXY_HOST:$PROXY_PORT/.well-known/masque/udp/{target_host}/{target_port}/
//! ```
//!
//! `target_host` кодируется процентно: IPv6 без скобок, `:` → `%3A`.

use http::uri::Authority;
use penguin_core::address::{Address, SocketAddress};
use penguin_transport::h3::{self, RequestStream, Response};
use penguin_transport::{TransportError, deadline};

use crate::error::{MasqueError, MasqueResult};

/// Значение `:protocol` расширенного `CONNECT` (RFC 9298, §3.4).
const PROTOCOL_CONNECT_UDP: &str = "connect-udp";

/// Значение заголовка, которым сервер подтверждает протокол капсул
/// (RFC 9297, §3.2; структурное булево «истина», RFC 8941, §3.3.6).
const CAPSULE_PROTOCOL_CONFIRMED: &str = "?1";

/// Собирает запрос `CONNECT-UDP` до `target` через прокси `authority`.
pub fn request(
    authority: &Authority,
    target: &SocketAddress,
    authorization: Option<&str>,
) -> h3::Request {
    let path = format!(
        "/.well-known/masque/udp/{}/{}/",
        encode_target_host(&target.host),
        target.port
    );
    let request = h3::Request::extended_connect(PROTOCOL_CONNECT_UDP, authority.as_str(), path)
        .header("capsule-protocol", CAPSULE_PROTOCOL_CONFIRMED);
    match authorization {
        Some(value) => request.header("authorization", value),
        None => request,
    }
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

/// `2xx` без `capsule-protocol: ?1` — нарушение формата (RFC 9298, §3.5), не отказ.
fn confirms_capsule_protocol(response: &Response) -> bool {
    response.header("capsule-protocol") == Some(CAPSULE_PROTOCOL_CONFIRMED)
}

/// Открывает поток `CONNECT-UDP`: срок, код ответа и подтверждение капсул.
/// Без расширенного `CONNECT` у прокси — [`h3::H3Error::Unsupported`] (ошибка настроек).
pub async fn perform(
    target: &SocketAddress,
    connection: &h3::Connection,
    request: &h3::Request,
) -> MasqueResult<RequestStream> {
    deadline::handshake("ответ прокси на CONNECT-UDP", async {
        let mut stream = connection
            .send_request(request)
            .await
            .map_err(TransportError::from)?;
        let response = stream.response().await.map_err(TransportError::from)?;

        if let Some(err) = outcome(response.status(), &target.to_wire()) {
            return Err(err);
        }
        if !confirms_capsule_protocol(&response) {
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
    use penguin_transport::h3::qpack::{Field, field};

    use super::*;

    fn authority() -> Authority {
        Authority::from_static("proxy.example.com:443")
    }

    fn target() -> SocketAddress {
        SocketAddress::domain("target.example.com", 53)
    }

    /// Поля запроса, как их увидит прокси.
    fn fields(request: &h3::Request) -> Vec<(String, String)> {
        field::decode(&request.encode(), usize::MAX)
            .expect("разбирается")
            .into_iter()
            .map(|f| {
                let text = |b: Vec<u8>| String::from_utf8(b).expect("текст");
                (text(f.name), text(f.value))
            })
            .collect()
    }

    fn get<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
        fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn the_request_uses_extended_connect_with_the_connect_udp_protocol() {
        let request = request(&authority(), &target(), None);
        assert!(request.is_extended_connect());
        let fields = fields(&request);
        assert_eq!(get(&fields, ":method"), Some("CONNECT"));
        assert_eq!(get(&fields, ":protocol"), Some("connect-udp"));
        assert_eq!(get(&fields, ":scheme"), Some("https"));
        assert_eq!(get(&fields, ":authority"), Some("proxy.example.com:443"));
        assert_eq!(get(&fields, "capsule-protocol"), Some("?1"));
    }

    #[test]
    fn the_path_carries_the_default_uri_template() {
        let fields = fields(&request(&authority(), &target(), None));
        assert_eq!(
            get(&fields, ":path"),
            Some("/.well-known/masque/udp/target.example.com/53/")
        );
    }

    #[test]
    fn an_ipv6_target_has_its_colons_escaped() {
        let target = SocketAddress::new(Address::Ip("2001:db8::42".parse().expect("адрес")), 443);
        let fields = fields(&request(&authority(), &target, None));
        assert_eq!(
            get(&fields, ":path"),
            Some("/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/")
        );
    }

    #[test]
    fn authorization_is_attached_when_configured() {
        let fields = fields(&request(
            &authority(),
            &target(),
            Some("Bearer секрет-токен"),
        ));
        assert_eq!(get(&fields, "authorization"), Some("Bearer секрет-токен"));
    }

    #[test]
    fn no_authorization_header_without_configuration() {
        let fields = fields(&request(&authority(), &target(), None));
        assert_eq!(get(&fields, "authorization"), None);
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
        let response = |capsule: Option<&str>| {
            let mut fields = vec![Field {
                name: b":status".to_vec(),
                value: b"200".to_vec(),
            }];
            fields.extend(capsule.map(|value| Field {
                name: b"capsule-protocol".to_vec(),
                value: value.as_bytes().to_vec(),
            }));
            Response::from_fields(fields).expect("ответ верен")
        };
        assert!(!confirms_capsule_protocol(&response(None)));
        assert!(!confirms_capsule_protocol(&response(Some("?0"))));
        assert!(confirms_capsule_protocol(&response(Some("?1"))));
    }
}
