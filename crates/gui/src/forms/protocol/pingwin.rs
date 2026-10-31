//! Pingwin — описание формы.

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали.
const DEFAULT_PORT: u16 = 443;

/// Чем идти: `auto` пробует QUIC и уходит на TCP, где режут UDP.
const TRANSPORTS: &[&str] = &["auto", "quic", "tcp"];

static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    // В профиле ключ лежит как `key`, в форме зовётся как у WireGuard.
    FieldSpec::text("server_public_key", &["key"], |s| s.server_public_key)
        .example(|s| s.pingwin_key_example)
        .required(|s| s.need_server_public_key),
    FieldSpec::secret("password", &["password"], |s| s.password).required(|s| s.need_password),
    FieldSpec::text("sni", &["sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::choice("transport", &["transport"], |s| s.transport, TRANSPORTS),
];

/// Как ссылка-приглашение ложится в поля:
/// `pingwin://<пароль>@<хост>:<порт>?key=<ключ>&sni=<имя в сертификате>#<профиль>`.
///
/// Ссылку собирает `pingwin-server link` (`penguin_pingwin::link`); разбор свой,
/// окно не зависит от протокола (AGENTS §1). Стороны сверяет один образец в
/// тестах здесь и там.
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let password = link.userinfo();
    if password.is_empty() {
        return Err(crate::i18n::s().link_no_password.to_owned());
    }
    let key = link
        .query
        .get("key")
        .ok_or_else(|| crate::i18n::s().need_server_public_key.to_owned())?;

    let mut values = vec![
        ("server", link.server(DEFAULT_PORT)),
        ("server_public_key", key),
        ("password", password),
    ];
    if let Some(sni) = link.query.get("sni") {
        values.push(("sni", sni));
    }
    Ok(values)
}

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "pingwin",
    label: "Pingwin",
    fields: FIELDS,
    schemes: &["pingwin://"],
    from_link: Some(from_link),
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forms::link;

    /// Образец, общий с тестом `penguin_pingwin::link`: правка формата ломает оба.
    const SAMPLE: &str = "pingwin://s3cret@203.0.113.5:443\
?key=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\
&sni=vpn.example.com#%D0%94%D0%BE%D0%BC%D0%B0";

    #[test]
    fn the_sample_link_from_the_server_fills_the_form() {
        let draft = link::parse(SAMPLE).expect("ссылка разбирается");
        assert_eq!(draft.spec().map(|spec| spec.id), Some("pingwin"));
        assert_eq!(draft.text("server"), "203.0.113.5:443");
        assert_eq!(draft.text("password"), "s3cret");
        assert_eq!(draft.text("sni"), "vpn.example.com");
        assert_eq!(
            draft.text("server_public_key"),
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
        );
        assert_eq!(draft.name, "Дома");
    }

    #[test]
    fn a_link_without_the_server_key_is_refused() {
        let raw = "pingwin://s3cret@example.com:443#Дома";
        assert!(link::parse(raw).is_err());
    }

    #[test]
    fn a_link_without_a_password_is_refused() {
        let raw = "pingwin://example.com:443?key=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
        assert!(link::parse(raw).is_err());
    }

    #[test]
    fn a_link_without_a_port_gets_the_usual_one() {
        let raw = "pingwin://s3cret@example.com\
?key=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
        let draft = link::parse(raw).expect("ссылка разбирается");
        assert_eq!(draft.text("server"), "example.com:443");
        assert_eq!(draft.text("sni"), "");
    }

    #[test]
    fn the_server_key_is_required_because_everything_stands_on_it() {
        let key = FIELDS
            .iter()
            .find(|field| field.key == "server_public_key")
            .expect("поле есть");
        assert!(key.required.is_some());
        assert_eq!(key.path, &["key"], "ключ ложится в настройки не туда");
    }

    #[test]
    fn a_new_profile_goes_by_whichever_transport_works() {
        let transport = FIELDS
            .iter()
            .find(|field| field.key == "transport")
            .expect("поле есть");
        assert!(transport.is_choice());
        assert_eq!(transport.default_text(), "auto");
    }

    #[test]
    fn the_password_is_hidden_and_required() {
        let password = FIELDS
            .iter()
            .find(|field| field.key == "password")
            .expect("поле есть");
        assert!(password.is_secret());
        assert!(password.required.is_some());
    }
}
