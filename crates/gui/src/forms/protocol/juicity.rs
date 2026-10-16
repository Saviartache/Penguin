//! Juicity — описание формы.

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали.
const DEFAULT_PORT: u16 = 443;

/// Управления перегрузкой нет: в коде эталона все значения сходятся к BBR.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::secret("uuid", &["uuid"], |s| s.uuid)
        .required(|s| s.need_uuid)
        .check(check::uuid),
    FieldSpec::secret("password", &["password"], |s| s.password).required(|s| s.need_password),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    // Не «не проверять»: сервер обязан предъявить именно эту цепочку.
    FieldSpec::text("pin_chain", &["tls", "pin_chain_sha256"], |s| {
        s.chain_fingerprint
    })
    .example(|s| s.chain_fingerprint_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
    // Датаграммы идут внутри того же соединения QUIC, DNS защищён.
    FieldSpec::flag("udp", &["udp"], |s| s.proxy_udp).on(),
];

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "juicity",
    label: "Juicity",
    fields: FIELDS,
    schemes: &["juicity://"],
    from_link: Some(from_link),
    note: None,
};

/// Как ссылка ложится в поля:
/// `juicity://uuid:пароль@хост:порт?sni=…&pinned_certchain_sha256=…#имя`.
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let (uuid, password) = link.uuid_password()?;

    let mut values = vec![
        ("server", link.server(DEFAULT_PORT)),
        ("uuid", uuid),
        ("password", password),
    ];

    if let Some(sni) = link.query.get("sni") {
        values.push(("sni", sni));
    }
    if let Some(pin) = link.query.get("pinned_certchain_sha256") {
        values.push(("pin_chain", pin));
    }
    // Эталон пишет и `allow_insecure=0`: проверка остаётся.
    if link.query.flag("allow_insecure") || link.query.flag("allowInsecure") {
        values.push(("insecure", "1".to_owned()));
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
    fn a_plain_link_fills_everything_it_should() {
        let values = parse(&format!("juicity://{UUID}:secret@example.com:8443#Дом"));
        assert_eq!(value(&values, "server"), Some("example.com:8443"));
        assert_eq!(value(&values, "uuid"), Some(UUID));
        assert_eq!(value(&values, "password"), Some("secret"));
    }

    #[test]
    fn the_colon_splits_the_uuid_from_the_password() {
        let values = parse(&format!("juicity://{UUID}:раз:два@example.com:443"));
        assert_eq!(value(&values, "uuid"), Some(UUID));
        assert_eq!(value(&values, "password"), Some("раз:два"));
    }

    #[test]
    fn a_link_without_a_password_is_refused() {
        let link = link::split(&format!("juicity://{UUID}@example.com:443")).expect("разбирается");
        assert!(from_link(&link).is_err());

        let link = link::split(&format!("juicity://{UUID}:@example.com:443")).expect("разбирается");
        assert!(from_link(&link).is_err());
    }

    #[test]
    fn a_link_without_a_uuid_is_refused() {
        let link = link::split("juicity://:secret@example.com:443").expect("разбирается");
        assert!(from_link(&link).is_err());
    }

    #[test]
    fn the_chain_fingerprint_is_carried_over() {
        let values = parse(&format!(
            "juicity://{UUID}:secret@example.com:443?sni=real.example.com&pinned_certchain_sha256=ABCD"
        ));
        assert_eq!(value(&values, "sni"), Some("real.example.com"));
        assert_eq!(value(&values, "pin_chain"), Some("ABCD"));
    }

    #[test]
    fn a_check_explicitly_left_on_is_not_turned_off() {
        let values = parse(&format!(
            "juicity://{UUID}:secret@example.com:443?allow_insecure=0"
        ));
        assert!(value(&values, "insecure").is_none());

        let values = parse(&format!(
            "juicity://{UUID}:secret@example.com:443?allow_insecure=1"
        ));
        assert_eq!(value(&values, "insecure"), Some("1"));
    }

    #[test]
    fn the_congestion_control_from_the_link_is_ignored() {
        let values = parse(&format!(
            "juicity://{UUID}:secret@example.com:443?congestion_control=cubic"
        ));
        assert!(values.iter().all(|(key, _)| *key != "congestion"));
    }

    #[test]
    fn a_link_without_extras_leaves_the_defaults_alone() {
        let values = parse(&format!("juicity://{UUID}:secret@example.com:443"));
        assert!(value(&values, "sni").is_none());
        assert!(value(&values, "pin_chain").is_none());
        assert!(value(&values, "insecure").is_none());
    }
}
