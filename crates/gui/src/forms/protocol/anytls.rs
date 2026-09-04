//! AnyTLS — описание формы.

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали.
const DEFAULT_PORT: u16 = 443;

/// Поля формы в том порядке, в каком они показываются.
///
/// Схемы дополнения здесь нет, и это не пропуск: её задаёт сервер и присылает
/// клиенту сам. Поле в форме затиралось бы первым же подключением.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::secret("password", &["password"], |s| s.password).required(|s| s.need_password),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
    // Датаграммы идут внутри той же сессии — значит, и запросы DNS защищены.
    FieldSpec::flag("udp", &["udp"], |s| s.proxy_udp).on(),
];

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "anytls",
    label: "AnyTLS",
    fields: FIELDS,
    schemes: &["anytls://"],
    from_link: Some(from_link),
};

/// Как ссылка ложится в поля.
///
/// ```text
///  anytls://пароль@хост:порт/?sni=…&insecure=1#имя
/// ```
///
/// В userinfo стоит **весь** пароль целиком, вместе с двоеточиями, если они в
/// нём есть: имени пользователя у AnyTLS нет. Этим ссылка похожа на
/// `trojan://` и не похожа на `tuic://`, где двоеточие — разделитель.
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let password = link.userinfo();
    if password.is_empty() {
        return Err(crate::i18n::s().link_no_password.to_owned());
    }

    let mut values = vec![
        ("server", link.server(DEFAULT_PORT)),
        ("password", password),
    ];

    if let Some(sni) = link.query.get("sni") {
        values.push(("sni", sni));
    }
    // Оба написания встречаются; смысл один — проверки сертификата не будет.
    if link.query.flag("insecure") || link.query.flag("allowInsecure") {
        values.push(("insecure", "1".to_owned()));
    }

    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forms::link;

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
    fn a_plain_link_fills_the_address_and_the_password() {
        let values = parse("anytls://letmein@example.com:8443#Дом");
        assert_eq!(value(&values, "server"), Some("example.com:8443"));
        assert_eq!(value(&values, "password"), Some("letmein"));
    }

    #[test]
    fn the_port_defaults_to_the_one_a_site_would_use() {
        let values = parse("anytls://letmein@example.com/");
        assert_eq!(value(&values, "server"), Some("example.com:443"));
    }

    #[test]
    fn a_colon_in_the_password_is_part_of_the_password() {
        // Имени пользователя у AnyTLS нет: делить строку не на что, и разрез
        // по двоеточию дал бы пароль, который не подойдёт.
        let values = parse("anytls://раз:два@example.com:443");
        assert_eq!(value(&values, "password"), Some("раз:два"));
    }

    #[test]
    fn a_link_without_a_password_is_refused() {
        let link = link::split("anytls://example.com:443").expect("разбирается");
        assert!(from_link(&link).is_err());
    }

    #[test]
    fn a_percent_encoded_password_is_decoded() {
        let values = parse("anytls://%D0%BF%D0%B0%D1%80%D0%BE%D0%BB%D1%8C@example.com:443");
        assert_eq!(value(&values, "password"), Some("пароль"));
    }

    #[test]
    fn the_settings_from_the_query_are_carried_over() {
        let values = parse("anytls://x@example.com:443/?sni=real.example.com&insecure=1");
        assert_eq!(value(&values, "sni"), Some("real.example.com"));
        assert_eq!(value(&values, "insecure"), Some("1"));
    }

    #[test]
    fn both_spellings_of_skipping_the_check_are_understood() {
        for raw in [
            "anytls://x@example.com:443/?insecure=1",
            "anytls://x@example.com:443/?allowInsecure=1",
        ] {
            assert_eq!(value(&parse(raw), "insecure"), Some("1"), "{raw}");
        }
    }

    #[test]
    fn an_address_written_as_a_number_survives() {
        let values = parse("anytls://x@[2409:8a71:6a00:1953::615]:8964/?insecure=1");
        assert_eq!(
            value(&values, "server"),
            Some("[2409:8a71:6a00:1953::615]:8964")
        );
    }

    #[test]
    fn a_link_without_extras_leaves_the_defaults_alone() {
        let values = parse("anytls://x@example.com:443");
        assert!(value(&values, "sni").is_none());
        assert!(value(&values, "insecure").is_none());
    }
}
