//! Pingwin — описание формы.

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали.
const DEFAULT_PORT: u16 = 443;

/// Поля формы в том порядке, в каком они показываются.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    // Имя поля в форме и его место в настройках нарочно разные: в профиле
    // ключ лежит коротко (`key`), а в форме зовётся так же, как у WireGuard.
    FieldSpec::text("server_public_key", &["key"], |s| s.server_public_key)
        .example(|s| s.pingwin_key_example)
        .required(|s| s.need_server_public_key),
    FieldSpec::secret("password", &["password"], |s| s.password).required(|s| s.need_password),
    FieldSpec::text("sni", &["sni"], |s| s.sni).example(|s| s.sni_example),
];

/// Как ссылка-приглашение ложится в поля.
///
/// ```text
/// pingwin://<пароль>@<хост>:<порт>?key=<ключ>&sni=<имя в сертификате>#<профиль>
/// ```
///
/// Собирает её сервер (`pingwin-server link`), формат описан на его стороне —
/// `penguin_pingwin::link`. Разбор здесь свой: окно не вправе зависеть от
/// крейта протокола (`AGENTS.md` §1). Связывает две стороны образец — одна и
/// та же строка в тесте здесь и там.
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
    note: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forms::link;

    /// Образец, по которому сверяются обе стороны.
    ///
    /// Ровно эта строка стоит в тесте `penguin_pingwin::link`, который её и
    /// собирает. Правка формата ломает оба теста сразу — в этом и смысл.
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
    fn the_password_is_hidden_and_required() {
        let password = FIELDS
            .iter()
            .find(|field| field.key == "password")
            .expect("поле есть");
        assert!(password.is_secret());
        assert!(password.required.is_some());
    }
}
