//! VLESS — описание формы.

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::carrier::{self, TRANSPORTS};
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали.
const DEFAULT_PORT: u16 = 443;

/// Чем шифруется соединение до сервера. `none` законен, когда TLS снимает сеть
/// доставки перед сервером. `reality` сверен только между Xray-core и sing-box:
/// непризнанного клиента сервер молча шлёт на настоящий сайт, об этом `SPEC.note`.
const SECURITY: &[&str] = &["tls", "none", "reality"];

/// Поля Reality не `.required()`: форма не видит других полей, недостающее ловит
/// `RealityConfig::validate`. Отпечатка браузера нет: поле выбора не бывает
/// пустым и заводило бы группу `reality` в профиле `tls`; умолчание — `chrome`.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::secret("uuid", &["uuid"], |s| s.uuid)
        .required(|s| s.need_uuid)
        .check(check::uuid),
    FieldSpec::choice("security", &["security"], |s| s.security, SECURITY),
    FieldSpec::choice("transport", &["transport"], |s| s.transport, TRANSPORTS),
    // Текст, не выбор: пустое законно, неверную комбинацию ловит `VlessConfig::validate`.
    FieldSpec::text("flow", &["flow"], |s| s.flow).example(|s| s.flow_example),
    FieldSpec::text("path", &["path"], |s| s.path).example(|s| s.path_example),
    FieldSpec::text("host", &["host"], |s| s.http_host).example(|s| s.optional_hint),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
    FieldSpec::text("reality_public_key", &["reality", "public_key"], |s| {
        s.server_public_key
    })
    .example(|s| s.reality_public_key_example),
    FieldSpec::text("reality_short_id", &["reality", "short_id"], |s| {
        s.reality_short_id
    })
    .example(|s| s.reality_short_id_example),
    FieldSpec::text("reality_server_name", &["reality", "server_name"], |s| {
        s.reality_server_name
    })
    .example(|s| s.reality_server_name_example),
    FieldSpec::flag("udp", &["udp"], |s| s.proxy_udp).on(),
];

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "vless",
    label: "VLESS",
    fields: FIELDS,
    schemes: &["vless://"],
    from_link: Some(from_link),
    // Строка про reality, но показывается всегда: при выборе сказать нельзя.
    note: Some(|s| s.reality_unverified),
};

/// Как ссылка ложится в поля.
///
/// ```text
///  vless://uuid@хост:порт?encryption=none&security=tls&type=xhttp&path=/…#имя
/// ```
///
/// `encryption` всегда `none`, поля под него нет.
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let uuid = link.userinfo();
    if uuid.is_empty() {
        return Err(crate::i18n::s().link_no_uuid.to_owned());
    }

    let mut values = vec![("server", link.server(DEFAULT_PORT)), ("uuid", uuid)];

    let is_reality = link.query.get("security").as_deref() == Some("reality");
    if let Some(security) = link.query.get("security") {
        values.push(("security", security));
    }
    values.extend(carrier::from_link(link)?);
    // Имя сайта у TLS и Reality — разные поля (`RealityConfig::validate` отказывает при обоих).
    if let Some(sni) = link.query.get("sni").or_else(|| link.query.get("peer")) {
        values.push((
            if is_reality {
                "reality_server_name"
            } else {
                "sni"
            },
            sni,
        ));
    }
    if link.query.flag("allowInsecure") || link.query.flag("insecure") {
        values.push(("insecure", "1".to_owned()));
    }
    // `pbk`/`sid` — имена параметров Reality в Xray-core (`RealityOpts`).
    if let Some(public_key) = link.query.get("pbk") {
        values.push(("reality_public_key", public_key));
    }
    if let Some(short_id) = link.query.get("sid") {
        values.push(("reality_short_id", short_id));
    }
    if let Some(flow) = link.query.get("flow") {
        values.push(("flow", flow));
    }

    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forms::link;
    use crate::forms::protocol::testing::{self, Values, value};

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn parse(raw: &str) -> Values {
        testing::parse(from_link, raw)
    }

    #[test]
    fn reality_is_offered_now_that_the_handshake_carries_traffic() {
        assert!(SECURITY.contains(&"reality"));
    }

    #[test]
    fn the_form_warns_that_reality_was_not_checked_against_a_live_server() {
        assert!(SPEC.note.is_some());
    }

    #[test]
    fn the_flow_field_is_exposed_in_the_form() {
        assert!(SPEC.index_of("flow").is_some());
    }

    #[test]
    fn a_plain_link_fills_the_address_and_the_uuid() {
        let values = parse(&format!("vless://{UUID}@example.com:8443#Дом"));
        assert_eq!(value(&values, "server"), Some("example.com:8443"));
        assert_eq!(value(&values, "uuid"), Some(UUID));
    }

    #[test]
    fn the_port_defaults_to_the_one_a_site_would_use() {
        let values = parse(&format!("vless://{UUID}@example.com"));
        assert_eq!(value(&values, "server"), Some("example.com:443"));
    }

    #[test]
    fn a_link_without_a_uuid_is_refused() {
        let link = link::split("vless://example.com:443").expect("разбирается");
        assert!(from_link(&link).is_err());
    }

    #[test]
    fn the_xhttp_settings_are_carried_over() {
        let values = parse(&format!(
            "vless://{UUID}@example.com:443?security=tls&type=xhttp&path=/up&host=cdn.example.com&sni=cdn.example.com"
        ));
        assert_eq!(value(&values, "security"), Some("tls"));
        assert_eq!(value(&values, "transport"), Some("xhttp"));
        assert_eq!(value(&values, "path"), Some("/up"));
        assert_eq!(value(&values, "host"), Some("cdn.example.com"));
        assert_eq!(value(&values, "sni"), Some("cdn.example.com"));
    }

    #[test]
    fn a_vision_flow_is_carried_over_from_the_link() {
        let values = parse(&format!(
            "vless://{UUID}@example.com:443?security=reality&pbk=abc&sid=ab12&sni=www.example.com&flow=xtls-rprx-vision"
        ));
        assert_eq!(value(&values, "flow"), Some("xtls-rprx-vision"));
    }

    #[test]
    fn reality_settings_are_carried_over_into_their_own_fields() {
        let values = parse(&format!(
            "vless://{UUID}@example.com:443?security=reality&pbk=abc&sid=ab12&sni=www.example.com"
        ));
        assert_eq!(value(&values, "security"), Some("reality"));
        assert_eq!(value(&values, "reality_public_key"), Some("abc"));
        assert_eq!(value(&values, "reality_short_id"), Some("ab12"));
        assert_eq!(
            value(&values, "reality_server_name"),
            Some("www.example.com")
        );
        // Иначе `RealityConfig::validate` отказала бы.
        assert_eq!(value(&values, "sni"), None);
    }

    #[test]
    fn an_unrecognized_security_still_carries_the_site_name_into_plain_sni() {
        let values = parse(&format!(
            "vless://{UUID}@example.com:443?security=tls&sni=cdn.example.com"
        ));
        assert_eq!(value(&values, "sni"), Some("cdn.example.com"));
        assert_eq!(value(&values, "reality_server_name"), None);
    }

    #[test]
    fn a_link_without_extras_leaves_the_defaults_alone() {
        let values = parse(&format!("vless://{UUID}@example.com:443"));
        assert!(value(&values, "transport").is_none());
        assert!(value(&values, "security").is_none());
        assert!(value(&values, "insecure").is_none());
    }
}
