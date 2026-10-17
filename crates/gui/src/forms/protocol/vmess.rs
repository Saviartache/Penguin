//! VMess — описание формы.

use penguin_core::base64;

use crate::forms::check;
use crate::forms::link::{self, Link};
use crate::forms::protocol::carrier::{self, TRANSPORTS};
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали.
const DEFAULT_PORT: u16 = 443;

/// Шифр тела; `auto` — умолчание протокола. `zero` отключает и шифрование, и
/// границы кусков, потому форма предупреждает ([`ProtocolSpec::note`]).
const CIPHERS: &[&str] = &["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"];

/// Шифрование до сервера, как у VLESS.
const SECURITY: &[&str] = &["tls", "none"];

/// `alterId` — число; протокол принимает только `0`, но ошибку лучше показать до сохранения.
fn check_alter_id(raw: &str) -> Result<(), String> {
    raw.trim()
        .parse::<u32>()
        .map(|_| ())
        .map_err(|_| crate::i18n::s().bad_alter_id.to_owned())
}

static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    // Не `check::uuid`: произвольный текст сервер сворачивает сам (`penguin_vmess::crypto::id::resolve`).
    FieldSpec::secret("id", &["id"], |s| s.vmess_id).required(|s| s.need_vmess_id),
    FieldSpec::text("alter_id", &["alter_id"], |s| s.alter_id).check(check_alter_id),
    FieldSpec::choice("cipher", &["cipher"], |s| s.method, CIPHERS),
    FieldSpec::choice("security", &["security"], |s| s.security, SECURITY),
    FieldSpec::choice("transport", &["transport"], |s| s.transport, TRANSPORTS),
    FieldSpec::text("path", &["path"], |s| s.path).example(|s| s.path_example),
    FieldSpec::text("host", &["host"], |s| s.http_host).example(|s| s.optional_hint),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
    FieldSpec::flag("udp", &["udp"], |s| s.proxy_udp).on(),
];

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "vmess",
    label: "VMess",
    fields: FIELDS,
    schemes: &["vmess://"],
    from_link: Some(from_link),
    note: Some(|s| s.vmess_zero_warning),
};

/// Как ссылка ложится в поля: `vmess://base64(json)` формата v2rayN
/// (`add`, `port`, `id`, `aid`, `net`, `host`, `path`, `tls`, `sni`).
///
/// Всё лежит внутри base64, поэтому [`crate::forms::link::split`] отдаёт его в
/// [`Link::host`]. `net` — наш `transport`, `aid` — `alter_id`; `security` формы
/// не равно `security` VMess (там это шифр, [`CIPHERS`]).
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let decoded =
        base64::decode(&link.host).map_err(|_| crate::i18n::s().link_not_a_link.to_owned())?;
    let text =
        String::from_utf8(decoded).map_err(|_| crate::i18n::s().link_not_a_link.to_owned())?;
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| crate::i18n::s().link_not_a_link.to_owned())?;

    let id = json
        .get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| crate::i18n::s().link_no_uuid.to_owned())?;
    let host = json
        .get("add")
        .and_then(serde_json::Value::as_str)
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| crate::i18n::s().link_no_host.to_owned())?;
    let port = text_field(&json, "port").unwrap_or_else(|| DEFAULT_PORT.to_string());

    let mut values = vec![
        ("server", link::join_host_port(host, &port)),
        ("id", id.to_owned()),
    ];

    if let Some(aid) = text_field(&json, "aid") {
        values.push(("alter_id", aid));
    }
    // Имя службы gRPC у v2rayN тоже в `path`.
    let net = json.get("net").and_then(serde_json::Value::as_str);
    let transport = carrier::transport(net.unwrap_or_default())?;
    if net.is_some() {
        values.push(("transport", transport.to_owned()));
    }
    if transport != "tcp" {
        if let Some(path) = json.get("path").and_then(serde_json::Value::as_str) {
            values.push(("path", path.to_owned()));
        }
        if let Some(http_host) = json.get("host").and_then(serde_json::Value::as_str) {
            values.push(("host", http_host.to_owned()));
        }
    }
    if let Some(sni) = json.get("sni").and_then(serde_json::Value::as_str) {
        values.push(("sni", sni.to_owned()));
    }
    let tls = json.get("tls").and_then(serde_json::Value::as_str);
    values.push((
        "security",
        if tls.is_some_and(|tls| tls.eq_ignore_ascii_case("tls")) {
            "tls".to_owned()
        } else {
            "none".to_owned()
        },
    ));

    Ok(values)
}

/// Поле JSON, которое провайдеры пишут то строкой, то числом.
fn text_field(json: &serde_json::Value, key: &str) -> Option<String> {
    match json.get(key)? {
        serde_json::Value::String(text) if !text.trim().is_empty() => Some(text.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forms::protocol::testing::{Values, value};

    fn link_for(json: &serde_json::Value) -> String {
        format!(
            "vmess://{}",
            base64::encode_url(json.to_string().as_bytes())
        )
    }

    fn parse(json: &serde_json::Value) -> Values {
        crate::forms::protocol::testing::parse(from_link, &link_for(json))
    }

    #[test]
    fn a_plain_link_fills_the_address_and_the_id() {
        let json = serde_json::json!({
            "add": "example.com", "port": 8443, "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
        });
        let values = parse(&json);
        assert_eq!(value(&values, "server"), Some("example.com:8443"));
        assert_eq!(
            value(&values, "id"),
            Some("b831381d-6324-4d53-ad4f-8cda48b30811")
        );
        assert_eq!(value(&values, "security"), Some("none"));
    }

    #[test]
    fn an_ipv6_address_is_put_in_brackets() {
        for add in ["2001:db8::1", "[2001:db8::1]"] {
            let json = serde_json::json!({ "add": add, "port": "8443", "id": "id" });
            let values = parse(&json);
            assert_eq!(value(&values, "server"), Some("[2001:db8::1]:8443"));
        }
    }

    #[test]
    fn the_port_defaults_when_missing() {
        let json = serde_json::json!({ "add": "example.com", "id": "id" });
        let values = parse(&json);
        assert_eq!(value(&values, "server"), Some("example.com:443"));
    }

    #[test]
    fn a_link_without_an_id_is_refused() {
        let json = serde_json::json!({ "add": "example.com", "port": 443 });
        let raw = link_for(&json);
        let link = link::split(&raw).expect("разбирается");
        assert!(from_link(&link).is_err());
    }

    #[test]
    fn tls_and_transport_settings_are_carried_over() {
        let json = serde_json::json!({
            "add": "example.com", "port": 443, "id": "id",
            "net": "grpc", "path": "svc", "host": "cdn.example.com",
            "tls": "tls", "sni": "cdn.example.com", "aid": "0",
        });
        let values = parse(&json);
        assert_eq!(value(&values, "transport"), Some("grpc"));
        assert_eq!(value(&values, "path"), Some("svc"));
        assert_eq!(value(&values, "host"), Some("cdn.example.com"));
        assert_eq!(value(&values, "sni"), Some("cdn.example.com"));
        assert_eq!(value(&values, "security"), Some("tls"));
        assert_eq!(value(&values, "alter_id"), Some("0"));
    }

    #[test]
    fn a_nonzero_alter_id_is_carried_over_and_left_to_the_protocol() {
        let json = serde_json::json!({
            "add": "example.com", "port": 443, "id": "id", "aid": 16,
        });
        let values = parse(&json);
        assert_eq!(value(&values, "alter_id"), Some("16"));
    }

    #[test]
    fn the_zero_cipher_is_named_in_the_note() {
        assert!(SPEC.note.is_some());
    }

    #[test]
    fn alter_id_must_be_a_number() {
        check_alter_id("0").expect("число");
        check_alter_id("  12 ").expect("число с пробелами");
        assert!(check_alter_id("не число").is_err());
    }
}
