//! Trojan — описание формы.

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали.
///
/// 443 — не обычай, а часть замысла: сервер обязан выглядеть обычным сайтом,
/// а сайт стоит на 443.
const DEFAULT_PORT: u16 = 443;

/// Чем поток переносится внутри TLS.
///
/// Порядок — это порядок в списке, и первое значение становится умолчанием
/// нового профиля. Сверху голый поток: он и есть настоящий Trojan, остальные
/// нужны только там, где по дороге стоит чужой обратный прокси.
const TRANSPORTS: &[&str] = &["tcp", "ws", "httpupgrade"];

/// Поля формы в том порядке, в каком они показываются.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    FieldSpec::secret("password", &["password"], |s| s.password).required(|s| s.need_password),
    // Список, а не строка: опечатка в имени переноса означала бы не «сервер
    // отказал», а «сервер молчит», и искали бы её в сети.
    FieldSpec::choice("transport", &["transport"], |s| s.transport, TRANSPORTS),
    FieldSpec::text("path", &["path"], |s| s.path).example(|s| s.path_example),
    FieldSpec::text("host", &["host"], |s| s.http_host).example(|s| s.optional_hint),
    FieldSpec::text("sni", &["tls", "sni"], |s| s.sni).example(|s| s.sni_example),
    FieldSpec::flag("insecure", &["tls", "insecure"], |s| s.insecure),
    // В отличие от SOCKS5 под TLS, датаграммы идут внутри того же потока —
    // значит, и запросы DNS защищены. Подпись поэтому обычная.
    FieldSpec::flag("udp", &["udp"], |s| s.proxy_udp).on(),
];

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "trojan",
    label: "Trojan",
    fields: FIELDS,
    schemes: &["trojan://"],
    from_link: Some(from_link),
};

/// Как ссылка ложится в поля.
///
/// В userinfo стоит **весь** пароль целиком, вместе с двоеточиями, если они в
/// нём есть: имени пользователя у Trojan нет вовсе, делить строку не на что.
/// Этим ссылка отличается от `socks5://`, где двоеточие — разделитель.
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let password = link.userinfo();
    if password.is_empty() {
        return Err(crate::i18n::s().link_no_password.to_owned());
    }

    let mut values = vec![
        ("server", link.server(DEFAULT_PORT)),
        ("password", password),
    ];

    // `peer` — то же самое имя для TLS под старым названием; конфигурации от
    // провайдеров приходят и с тем, и с другим.
    if let Some(sni) = link.query.get("sni").or_else(|| link.query.get("peer")) {
        values.push(("sni", sni));
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
    // Оба написания встречаются; смысл один — проверки сертификата не будет.
    if link.query.flag("allowInsecure") || link.query.flag("insecure") {
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
        let values = parse("trojan://secret@example.com:8443#Дом");
        assert_eq!(value(&values, "server"), Some("example.com:8443"));
        assert_eq!(value(&values, "password"), Some("secret"));
    }

    #[test]
    fn the_port_defaults_to_the_one_a_site_would_use() {
        // Сервер обязан выглядеть обычным сайтом, а сайт стоит на 443.
        let values = parse("trojan://secret@example.com");
        assert_eq!(value(&values, "server"), Some("example.com:443"));
    }

    #[test]
    fn a_colon_in_the_password_is_part_of_the_password() {
        // Имени пользователя у Trojan нет: делить строку не на что, и разрез
        // по двоеточию дал бы пароль, который не подойдёт.
        let values = parse("trojan://раз:два@example.com:443");
        assert_eq!(value(&values, "password"), Some("раз:два"));
    }

    #[test]
    fn a_link_without_a_password_is_refused() {
        let link = link::split("trojan://example.com:443").expect("разбирается");
        assert!(from_link(&link).is_err());
    }

    #[test]
    fn the_websocket_settings_are_carried_over() {
        let values = parse("trojan://secret@example.com:443?type=ws&path=/ws&host=cdn.example.com");
        assert_eq!(value(&values, "transport"), Some("ws"));
        assert_eq!(value(&values, "path"), Some("/ws"));
        assert_eq!(value(&values, "host"), Some("cdn.example.com"));
    }

    #[test]
    fn both_names_of_the_tls_name_are_understood() {
        // Конфигурации от провайдеров приходят и с тем, и с другим.
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
        // Пустое поле не пишется вовсе, и перенос остаётся тем, что стоит в
        // описании: `tcp`.
        let values = parse("trojan://secret@example.com:443");
        assert!(value(&values, "transport").is_none());
        assert!(value(&values, "path").is_none());
        assert!(value(&values, "insecure").is_none());
    }
}
