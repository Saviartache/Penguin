//! Trojan — описание формы.

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::carrier::{self, TRANSPORTS};
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали: сервер выглядит сайтом, а сайт на 443.
const DEFAULT_PORT: u16 = 443;

static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::secret("password", &["password"], |s| s.password).required(|s| s.need_password),
    // Список: опечатка в переносе даёт молчащий сервер.
    FieldSpec::choice("transport", &["transport"], |s| s.transport, TRANSPORTS),
    FieldSpec::text("path", &["path"], |s| s.path).example(|s| s.path_example),
    FieldSpec::text("host", &["host"], |s| s.http_host).example(|s| s.optional_hint),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
    // Датаграммы идут внутри того же потока, DNS защищён.
    FieldSpec::flag("udp", &["udp"], |s| s.proxy_udp).on(),
];

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "trojan",
    label: "Trojan",
    fields: FIELDS,
    schemes: &["trojan://"],
    from_link: Some(from_link),
    note: None,
};

/// Как ссылка ложится в поля. Имени пользователя нет, userinfo — весь пароль,
/// включая двоеточия.
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let password = link.userinfo();
    if password.is_empty() {
        return Err(crate::i18n::s().link_no_password.to_owned());
    }

    let mut values = vec![
        ("server", link.server(DEFAULT_PORT)),
        ("password", password),
    ];

    // `peer` — старое имя `sni`.
    if let Some(sni) = link.query.get("sni").or_else(|| link.query.get("peer")) {
        values.push(("sni", sni));
    }
    values.extend(carrier::from_link(link)?);
    if link.query.flag("allowInsecure") || link.query.flag("insecure") {
        values.push(("insecure", "1".to_owned()));
    }

    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forms::link;
    use crate::forms::protocol::testing::{self, Values, value};

    fn parse(raw: &str) -> Values {
        testing::parse(from_link, raw)
    }

    #[test]
    fn a_plain_link_fills_the_address_and_the_password() {
        let values = parse("trojan://secret@example.com:8443#Дом");
        assert_eq!(value(&values, "server"), Some("example.com:8443"));
        assert_eq!(value(&values, "password"), Some("secret"));
    }

    #[test]
    fn the_port_defaults_to_the_one_a_site_would_use() {
        let values = parse("trojan://secret@example.com");
        assert_eq!(value(&values, "server"), Some("example.com:443"));
    }

    #[test]
    fn a_colon_in_the_password_is_part_of_the_password() {
        let values = parse("trojan://раз:два@example.com:443");
        assert_eq!(value(&values, "password"), Some("раз:два"));
    }

    #[test]
    fn a_link_without_a_password_is_refused() {
        let link = link::split("trojan://example.com:443").expect("разбирается");
        assert!(from_link(&link).is_err());
    }

    #[test]
    fn the_grpc_settings_are_carried_over() {
        // Путь gRPC в ссылке Xray зовётся `serviceName`.
        let values =
            parse("trojan://secret@example.com:443?type=grpc&serviceName=svc&host=cdn.example.com");
        assert_eq!(value(&values, "transport"), Some("grpc"));
        assert_eq!(value(&values, "path"), Some("svc"));
        assert_eq!(value(&values, "host"), Some("cdn.example.com"));
    }

    #[test]
    fn a_websocket_link_is_refused() {
        let link =
            link::split("trojan://secret@example.com:443?type=ws&path=/ws").expect("разбирается");
        assert!(from_link(&link).is_err());
    }

    #[test]
    fn both_names_of_the_tls_name_are_understood() {
        let values = parse("trojan://secret@example.com:443?sni=cdn.example.com");
        assert_eq!(value(&values, "sni"), Some("cdn.example.com"));

        let values = parse("trojan://secret@example.com:443?peer=cdn.example.com");
        assert_eq!(value(&values, "sni"), Some("cdn.example.com"));
    }

    #[test]
    fn both_spellings_of_skipping_the_check_are_understood() {
        for raw in [
            "trojan://secret@example.com:443?allowInsecure=1",
            "trojan://secret@example.com:443?insecure=1",
        ] {
            assert_eq!(value(&parse(raw), "insecure"), Some("1"), "{raw}");
        }
    }

    #[test]
    fn a_link_without_extras_leaves_the_defaults_alone() {
        let values = parse("trojan://secret@example.com:443");
        assert!(value(&values, "transport").is_none());
        assert!(value(&values, "path").is_none());
        assert!(value(&values, "insecure").is_none());
    }
}
