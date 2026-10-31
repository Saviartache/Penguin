//! Shadowsocks — описание формы.

use penguin_core::base64;

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали.
const DEFAULT_PORT: u16 = 8388;

/// Методы по порядку показа; первый — умолчание. Потоковых шифров нет: они не
/// заверяют данные. У `2022-blake3-*` поле «пароль» несёт base64-ключ (PSK).
const METHODS: &[&str] = &[
    "aes-256-gcm",
    "aes-128-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

/// Длина PSK метода 2022; `None` — обычный пароль.
///
/// Дубль `penguin_shadowsocks::method::Method2022`: `gui` не зависит от `protocols/*`.
fn method2022_key_len(method: &str) -> Option<usize> {
    match method {
        "2022-blake3-aes-128-gcm" => Some(16),
        "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => Some(32),
        _ => None,
    }
}

static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    // Список: опечатка в методе даёт соединение, которое ничего не передаёт.
    FieldSpec::choice("method", &["method"], |s| s.method, METHODS).required(|s| s.need_method),
    FieldSpec::secret("password", &["password"], |s| s.password).required(|s| s.need_password),
    FieldSpec::flag("udp", &["udp"], |s| s.proxy_udp).on(),
];

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "shadowsocks",
    label: "Shadowsocks",
    fields: FIELDS,
    schemes: &["ss://"],
    from_link: Some(from_link),
};

/// Как ссылка ложится в поля. Записей две, обе в ходу:
///
/// ```text
///  ss://base64(метод:пароль)@хост:порт#имя     SIP002
///  ss://base64(метод:пароль@хост:порт)#имя     прежняя
/// ```
///
/// У методов 2022 длина ключа проверяется сразу: сервер с ключом не той длины
/// молчит, и принятая ссылка выглядела бы рабочей до первого подключения.
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let userinfo = link.userinfo();
    let (credentials, server) = if userinfo.is_empty() {
        let decoded = decode(&link.host)?;
        let (credentials, server) = decoded
            .rsplit_once('@')
            .ok_or_else(|| crate::i18n::s().link_no_host.to_owned())?;
        (credentials.to_owned(), with_port(server))
    } else {
        (decode_or_keep(&userinfo), link.server(DEFAULT_PORT))
    };

    let (method, password) = credentials
        .split_once(':')
        .ok_or_else(|| crate::i18n::s().link_no_password.to_owned())?;
    if password.is_empty() {
        return Err(crate::i18n::s().link_no_password.to_owned());
    }
    if let Some(key_len) = method2022_key_len(method) {
        base64::decode_exact(password, key_len, "ключ Shadowsocks 2022")
            .map_err(|_| crate::i18n::s().link_not_a_link.to_owned())?;
    }

    Ok(vec![
        ("server", server),
        ("method", method.to_owned()),
        ("password", password.to_owned()),
    ])
}

fn decode(raw: &str) -> Result<String, String> {
    let bytes = base64::decode(raw).map_err(|_| crate::i18n::s().link_not_a_link.to_owned())?;
    String::from_utf8(bytes).map_err(|_| crate::i18n::s().link_not_a_link.to_owned())
}

/// Base64, а если это не он — как есть: userinfo иногда пишут открытым текстом.
fn decode_or_keep(userinfo: &str) -> String {
    match decode(userinfo) {
        Ok(decoded) if decoded.contains(':') => decoded,
        _ => userinfo.to_owned(),
    }
}

/// Дописывает порт по умолчанию. Голый IPv6 (`2001:db8::1`) порта не несёт и
/// берётся в скобки, иначе он не разберётся.
fn with_port(server: &str) -> String {
    if let Some(rest) = server.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((_, tail)) if tail.starts_with(':') && tail.len() > 1 => server.to_owned(),
            _ => format!("{server}:{DEFAULT_PORT}"),
        };
    }

    if server.matches(':').count() > 1 {
        return format!("[{server}]:{DEFAULT_PORT}");
    }

    match server.rsplit_once(':') {
        Some((head, tail))
            if !head.is_empty() && !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) =>
        {
            server.to_owned()
        }
        _ => format!("{server}:{DEFAULT_PORT}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forms::link;
    use crate::forms::protocol::testing::{self, Values, value};

    fn parse(raw: &str) -> Values {
        testing::parse(from_link, raw)
    }

    fn sip002(credentials: &str, server: &str) -> String {
        format!(
            "ss://{}@{server}",
            base64::encode_url(credentials.as_bytes())
        )
    }

    fn legacy(all: &str) -> String {
        format!("ss://{}", base64::encode_url(all.as_bytes()))
    }

    #[test]
    fn the_current_form_is_read() {
        let values = parse(&sip002("aes-256-gcm:secret", "example.com:8388"));
        assert_eq!(value(&values, "server"), Some("example.com:8388"));
        assert_eq!(value(&values, "method"), Some("aes-256-gcm"));
        assert_eq!(value(&values, "password"), Some("secret"));
    }

    #[test]
    fn the_older_form_is_read_too() {
        let values = parse(&legacy("chacha20-ietf-poly1305:secret@example.com:9000"));
        assert_eq!(value(&values, "server"), Some("example.com:9000"));
        assert_eq!(value(&values, "method"), Some("chacha20-ietf-poly1305"));
        assert_eq!(value(&values, "password"), Some("secret"));
    }

    #[test]
    fn plain_credentials_are_accepted() {
        let values = parse("ss://aes-128-gcm:secret@example.com:8388");
        assert_eq!(value(&values, "method"), Some("aes-128-gcm"));
        assert_eq!(value(&values, "password"), Some("secret"));
    }

    #[test]
    fn a_colon_in_the_password_stays_in_the_password() {
        let values = parse(&sip002("aes-256-gcm:раз:два", "example.com:8388"));
        assert_eq!(value(&values, "password"), Some("раз:два"));
    }

    #[test]
    fn the_port_defaults_when_the_older_form_omits_it() {
        let values = parse(&legacy("aes-256-gcm:secret@example.com"));
        assert_eq!(value(&values, "server"), Some("example.com:8388"));
    }

    #[test]
    fn an_at_sign_in_the_password_does_not_confuse_the_older_form() {
        // Адрес отделяется последним `@`.
        let values = parse(&legacy("aes-256-gcm:па@роль@example.com:8388"));
        assert_eq!(value(&values, "password"), Some("па@роль"));
        assert_eq!(value(&values, "server"), Some("example.com:8388"));
    }

    #[test]
    fn a_link_without_a_password_is_refused() {
        let link = link::split(&sip002("aes-256-gcm:", "example.com:8388")).expect("разбирается");
        assert!(from_link(&link).is_err());

        let link = link::split(&sip002("aes-256-gcm", "example.com:8388")).expect("разбирается");
        assert!(from_link(&link).is_err());
    }

    #[test]
    fn the_2022_methods_are_offered_in_the_choice() {
        for method in [
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ] {
            assert!(METHODS.contains(&method), "{method}");
        }
    }

    #[test]
    fn a_2022_link_with_a_key_of_the_right_length_is_read() {
        let key = base64::encode(&[7u8; 16]);
        let values = parse(&sip002(
            &format!("2022-blake3-aes-128-gcm:{key}"),
            "example.com:8388",
        ));
        assert_eq!(value(&values, "method"), Some("2022-blake3-aes-128-gcm"));
        assert_eq!(value(&values, "password"), Some(key.as_str()));
    }

    #[test]
    fn a_2022_link_with_a_key_of_the_wrong_length_is_not_silently_accepted() {
        let short_key = base64::encode(&[7u8; 10]);
        let link = link::split(&sip002(
            &format!("2022-blake3-aes-128-gcm:{short_key}"),
            "example.com:8388",
        ))
        .expect("ссылка разбирается");
        assert!(from_link(&link).is_err());
    }

    #[test]
    fn a_2022_link_whose_key_is_not_base64_is_not_silently_accepted() {
        let link = link::split(&sip002(
            "2022-blake3-aes-128-gcm:не base64 и не ключ",
            "example.com:8388",
        ))
        .expect("ссылка разбирается");
        assert!(from_link(&link).is_err());
    }

    #[test]
    fn a_plain_aead_password_is_not_held_to_the_2022_key_length() {
        let values = parse(&sip002("aes-256-gcm:любой пароль", "example.com:8388"));
        assert_eq!(value(&values, "password"), Some("любой пароль"));
    }

    #[test]
    fn nonsense_instead_of_base64_is_reported() {
        let link = link::split("ss://это-не-base64").expect("разбирается");
        assert!(from_link(&link).is_err());
    }

    #[test]
    fn a_port_is_told_apart_from_the_rest_of_the_address() {
        assert_eq!(with_port("example.com:9000"), "example.com:9000");
        assert_eq!(with_port("example.com"), "example.com:8388");
        assert_eq!(with_port("[2001:db8::1]:9000"), "[2001:db8::1]:9000");
        assert_eq!(with_port("[2001:db8::1]"), "[2001:db8::1]:8388");
    }

    #[test]
    fn a_bare_ipv6_gets_its_brackets_back() {
        assert_eq!(with_port("2001:db8::1"), "[2001:db8::1]:8388");
        check::server_address(&with_port("2001:db8::1")).expect("разбирается");
    }
}
