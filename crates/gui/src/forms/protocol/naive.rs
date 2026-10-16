//! NaiveProxy — описание формы. Две записи: по HTTP/2 и по HTTP/3.

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали.
const DEFAULT_PORT: u16 = 443;

/// Флага TLS нет: протокол неотличим от HTTPS, открытый разговор снял бы маску.
/// Имя и пароль необязательны: сервер без учётных данных бывает.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::text("username", &["username"], |s| s.username).example(|s| s.optional_hint),
    FieldSpec::secret("password", &["password"], |s| s.password).example(|s| s.optional_hint),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
];

/// `CONNECT` поверх HTTP/2.
pub static HTTP2: ProtocolSpec = ProtocolSpec {
    id: "http2",
    label: "NaiveProxy (HTTP/2)",
    fields: FIELDS,
    schemes: &["naive+https://"],
    from_link: Some(from_link),
    note: None,
};

/// `CONNECT` поверх HTTP/3 (QUIC). Отдельной записью: сервер слушает на другом порту.
pub static HTTP3: ProtocolSpec = ProtocolSpec {
    id: "http3",
    label: "NaiveProxy (HTTP/3)",
    fields: FIELDS,
    schemes: &["naive+quic://"],
    from_link: Some(from_link),
    note: None,
};

/// Как ссылка ложится в поля: `naive+https://имя:пароль@хост:порт?sni=…#имя`
/// (HTTP/2) и `naive+quic://…` (HTTP/3), схемы NekoBox и v2rayN. Двоеточие в
/// userinfo — разделитель (Basic). `padding` и `extra-headers` не переносятся.
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let mut values = vec![("server", link.server(DEFAULT_PORT))];

    let userinfo = link.userinfo();
    if !userinfo.is_empty() {
        let (username, password) = userinfo.split_once(':').unwrap_or((&userinfo, ""));
        values.push(("username", username.to_owned()));
        values.push(("password", password.to_owned()));
    }
    if let Some(sni) = link.query.get("sni") {
        values.push(("sni", sni));
    }
    if link.query.flag("insecure") || link.query.flag("allowInsecure") {
        values.push(("insecure", "1".to_owned()));
    }

    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn there_is_no_tls_switch_because_tls_is_the_whole_point() {
        assert!(FIELDS.iter().all(|field| field.key != "tls"));
    }

    #[test]
    fn neither_the_name_nor_the_password_is_required() {
        for key in ["username", "password"] {
            let field = FIELDS
                .iter()
                .find(|field| field.key == key)
                .expect("поле есть");
            assert!(field.required.is_none(), "{key}");
        }
    }

    #[test]
    fn both_transports_ask_for_the_same_things() {
        assert_eq!(HTTP2.fields.len(), HTTP3.fields.len());
        assert_ne!(HTTP2.id, HTTP3.id);
    }

    #[test]
    fn a_link_fills_the_form_and_picks_the_transport() {
        let draft = crate::forms::link::parse(
            "naive+https://friend:s3cr:et@example.com:8443?sni=cdn.example.com#Друг",
        )
        .expect("разбирается");
        assert_eq!(draft.protocol(), HTTP2.id);
        assert_eq!(draft.name, "Друг");

        let link = crate::forms::link::split(
            "naive+quic://friend:s3cr:et@example.com:8443?sni=cdn.example.com",
        )
        .expect("разбирается");
        let values = from_link(&link).expect("поля заполняются");
        assert_eq!(
            values,
            [
                ("server", "example.com:8443".to_owned()),
                ("username", "friend".to_owned()),
                ("password", "s3cr:et".to_owned()),
                ("sni", "cdn.example.com".to_owned()),
            ]
        );
        assert_eq!(
            crate::forms::protocol::by_scheme(&link.scheme).map(|spec| spec.id),
            Some(HTTP3.id)
        );
    }

    #[test]
    fn there_is_no_udp_switch_because_there_is_no_udp() {
        assert!(FIELDS.iter().all(|field| field.key != "udp"));
    }
}
