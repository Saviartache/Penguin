//! VLESS — описание формы.

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали.
const DEFAULT_PORT: u16 = 443;

/// Чем шифруется соединение до сервера.
///
/// `tls` первым: это обычный случай. `none` законен ровно тогда, когда TLS
/// снимает кто-то другой — сеть доставки перед сервером; сам по себе он
/// означает, что UUID уходит по сети открытым текстом.
const SECURITY: &[&str] = &["tls", "none"];

/// Чем переносится поток.
const TRANSPORTS: &[&str] = &["tcp", "ws", "httpupgrade"];

/// Поля формы в том порядке, в каком они показываются.
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
    FieldSpec::text("path", &["path"], |s| s.path).example(|s| s.path_example),
    FieldSpec::text("host", &["host"], |s| s.http_host).example(|s| s.optional_hint),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
    FieldSpec::flag("udp", &["udp"], |s| s.proxy_udp).on(),
];

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "vless",
    label: "VLESS",
    fields: FIELDS,
    schemes: &["vless://"],
    from_link: Some(from_link),
    note: None,
};

/// Как ссылка ложится в поля.
///
/// ```text
///  vless://uuid@хост:порт?encryption=none&security=tls&type=ws&path=/…#имя
/// ```
///
/// `encryption` в ссылке всегда `none` и означает не «без шифрования», а
/// «своего шифрования у протокола нет». Поля под него в форме нет: другого
/// значения не бывает, а показывать переключатель с одним положением — значит
/// спрашивать о том, чего не выбирают.
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let uuid = link.userinfo();
    if uuid.is_empty() {
        return Err(crate::i18n::s().link_no_uuid.to_owned());
    }

    let mut values = vec![("server", link.server(DEFAULT_PORT)), ("uuid", uuid)];

    if let Some(security) = link.query.get("security") {
        // `reality` и `xtls` сюда попасть могут, и это не наш случай: пусть
        // отвергнет протокол — с объяснением, которого у окна нет.
        values.push(("security", security));
    }
    if let Some(transport) = link.query.get("type") {
        values.push(("transport", transport));
    }
    if let Some(path) = link.query.get("path") {
        values.push(("path", path));
    }
    if let Some(host) = link.query.get("host") {
        values.push(("host", host));
    }
    if let Some(sni) = link.query.get("sni").or_else(|| link.query.get("peer")) {
        values.push(("sni", sni));
    }
    if link.query.flag("allowInsecure") || link.query.flag("insecure") {
        values.push(("insecure", "1".to_owned()));
    }

    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forms::link;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn parse(raw: &str) -> Vec<(&'static str, String)> {
        let link = link::split(raw).expect("ссылка разбирается");
        from_link(&link).expect("поля заполняются")
    }

    fn value<'a>(values: &'a [(&'static str, String)], key: &str) -> Option<&'a str> {
        values
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value.as_str())
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
    fn the_websocket_settings_are_carried_over() {
        let values = parse(&format!(
            "vless://{UUID}@example.com:443?security=tls&type=ws&path=/ws&host=cdn.example.com&sni=cdn.example.com"
        ));
        assert_eq!(value(&values, "security"), Some("tls"));
        assert_eq!(value(&values, "transport"), Some("ws"));
        assert_eq!(value(&values, "path"), Some("/ws"));
        assert_eq!(value(&values, "host"), Some("cdn.example.com"));
        assert_eq!(value(&values, "sni"), Some("cdn.example.com"));
    }

    #[test]
    fn reality_is_carried_over_and_left_to_the_protocol() {
        // Окно не знает, чего протокол не умеет, — и объяснить это некому,
        // кроме самого протокола.
        let values = parse(&format!("vless://{UUID}@example.com:443?security=reality"));
        assert_eq!(value(&values, "security"), Some("reality"));
    }

    #[test]
    fn a_link_without_extras_leaves_the_defaults_alone() {
        let values = parse(&format!("vless://{UUID}@example.com:443"));
        assert!(value(&values, "transport").is_none());
        assert!(value(&values, "security").is_none());
        assert!(value(&values, "insecure").is_none());
    }
}
