//! Shadowsocks — описание формы.

use penguin_core::base64;

use crate::forms::check;
use crate::forms::link::Link;
use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

/// Порт, если в ссылке его не указали.
///
/// 8388 — обычай, а не правило, но именно он стоит в примерах на сервере.
const DEFAULT_PORT: u16 = 8388;

/// Методы шифрования в порядке показа.
///
/// Первый становится умолчанием нового профиля. `aes-256-gcm` сверху не
/// потому, что он лучший, а потому что его настраивают чаще всего: на нём
/// стоит большинство серверов.
///
/// Потоковых шифров прежних версий (`aes-256-cfb`, `rc4-md5`) в списке нет, и
/// крейт протокола их тоже не принимает: они не заверяют данные, то есть
/// правку по дороге не заметит ни клиент, ни сервер.
const METHODS: &[&str] = &["aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305"];

/// Поля формы в том порядке, в каком они показываются.
static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("server", &["server"], |s| s.server_address)
        .example(|s| s.server_address_example)
        .required(|s| s.need_server)
        .check(check::server_address),
    // Список, а не строка: метод — часть договора с сервером, и опечатка в
    // нём означает не «сервер отказал», а соединение, которое открывается и
    // ничего не передаёт.
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

/// Как ссылка ложится в поля.
///
/// Записей у `ss://` две, и обе встречаются:
///
/// ```text
///  ss://base64(метод:пароль)@хост:порт#имя     сегодняшняя (SIP002)
///  ss://base64(метод:пароль@хост:порт)#имя     прежняя, целиком в base64
/// ```
///
/// Отличаются они наличием `@` **снаружи** base64. Разобрать надо обе: ссылки
/// рассылают до сих пор в обеих, и отвергнутая ссылка выглядит как поломка
/// клиента, а не как устаревший формат.
fn from_link(link: &Link) -> Result<Vec<(&'static str, String)>, String> {
    let userinfo = link.userinfo();
    let (credentials, server) = if userinfo.is_empty() {
        // Прежняя запись: в base64 лежит всё вместе с адресом.
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

    Ok(vec![
        ("server", server),
        ("method", method.to_owned()),
        ("password", password.to_owned()),
    ])
}

/// Разбирает base64 или отдаёт понятную ошибку.
fn decode(raw: &str) -> Result<String, String> {
    let bytes = base64::decode(raw).map_err(|_| crate::i18n::s().link_not_a_link.to_owned())?;
    String::from_utf8(bytes).map_err(|_| crate::i18n::s().link_not_a_link.to_owned())
}

/// Разбирает base64, а если это не он — оставляет как есть.
///
/// В сегодняшней записи userinfo обязан быть base64, но пишут туда и открытым
/// текстом: `ss://aes-256-gcm:пароль@хост:порт`. Отвергать такую ссылку
/// незачем — разобрать её можно однозначно.
fn decode_or_keep(userinfo: &str) -> String {
    match decode(userinfo) {
        Ok(decoded) if decoded.contains(':') => decoded,
        _ => userinfo.to_owned(),
    }
}

/// Дописывает порт по умолчанию, если в адресе его нет.
///
/// Тонкость здесь одна и вся про IPv6. Порт от адреса отделяется двоеточием, а
/// в IPv6 двоеточий и так полно — ровно поэтому его берут в скобки. Значит:
///
/// - `[2001:db8::1]:9000` — скобки и порт, всё ясно;
/// - `[2001:db8::1]` — скобки без порта, порт дописывается;
/// - `2001:db8::1` — **порта здесь нет и быть не может**, и адрес надо ещё и
///   взять в скобки, иначе он не разберётся ни у нас, ни у сервера;
/// - `example.com:9000` и `example.com` — обычный случай.
fn with_port(server: &str) -> String {
    if let Some(rest) = server.strip_prefix('[') {
        // В скобках: порт — то, что после закрывающей.
        return match rest.split_once(']') {
            Some((_, tail)) if tail.starts_with(':') && tail.len() > 1 => server.to_owned(),
            _ => format!("{server}:{DEFAULT_PORT}"),
        };
    }

    // Два двоеточия и больше без скобок — это голый IPv6: порта в нём нет.
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

    /// Собирает ссылку сегодняшней записи.
    fn sip002(credentials: &str, server: &str) -> String {
        format!(
            "ss://{}@{server}",
            base64::encode_url(credentials.as_bytes())
        )
    }

    /// Собирает ссылку прежней записи.
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
        // Их рассылают до сих пор; отвергнутая ссылка выглядит поломкой
        // клиента, а не устаревшим форматом.
        let values = parse(&legacy("chacha20-ietf-poly1305:secret@example.com:9000"));
        assert_eq!(value(&values, "server"), Some("example.com:9000"));
        assert_eq!(value(&values, "method"), Some("chacha20-ietf-poly1305"));
        assert_eq!(value(&values, "password"), Some("secret"));
    }

    #[test]
    fn plain_credentials_are_accepted() {
        // Записывать userinfo открытым текстом не по правилам, но так пишут,
        // и разобрать это можно однозначно.
        let values = parse("ss://aes-128-gcm:secret@example.com:8388");
        assert_eq!(value(&values, "method"), Some("aes-128-gcm"));
        assert_eq!(value(&values, "password"), Some("secret"));
    }

    #[test]
    fn a_colon_in_the_password_stays_in_the_password() {
        // Метод отделяется первым двоеточием: остальные принадлежат паролю.
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
        // Адрес отделяется **последним** `@`: всё до него — пароль.
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
        // Порта в нём нет и быть не может: двоеточие занято самим адресом.
        // Без скобок такой адрес не разберётся ни у нас, ни на сервере.
        assert_eq!(with_port("2001:db8::1"), "[2001:db8::1]:8388");
        check::server_address(&with_port("2001:db8::1")).expect("разбирается");
    }
}
