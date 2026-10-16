//! Разбор ссылки-приглашения.
//!
//! ```text
//! hy2://source:s3cret@example.net:3478?sni=example.net&insecure=0#source
//! socks5://penguin:s3cret@127.0.0.1:1080#Дома
//! ```
//!
//! Общее здесь: схема, userinfo, адрес, запрос, имя после `#`. Что куда
//! положить, знает протокол ([`crate::forms::protocol::ProtocolSpec::from_link`]).
//!
//! `+` в запросе — пробел (ссылки делает Go, `url.Query()` читает форму), в
//! userinfo — плюс. Порт может быть диапазоном (`host:20000-30000`): он
//! передаётся как есть.

use crate::forms::protocol;
use crate::forms::server::Draft;

/// Похожа ли строка на ссылку-приглашение; отличает вставку от набираемого имени.
pub fn looks_like_link(raw: &str) -> bool {
    let raw = raw.trim().to_lowercase();
    protocol::ALL
        .iter()
        .flat_map(|spec| spec.schemes)
        .any(|scheme| raw.len() > scheme.len() && raw.starts_with(scheme))
}

/// Разбирает ссылку в черновик; `Err` — текст для показа как есть.
pub fn parse(raw: &str) -> Result<Draft, String> {
    let link = split(raw)?;
    let spec = protocol::by_scheme(&link.scheme)
        .ok_or_else(|| crate::i18n::s().link_not_a_link.to_owned())?;

    let Some(from_link) = spec.from_link else {
        return Err(crate::i18n::s().link_not_a_link.to_owned());
    };

    let mut draft = Draft::new(spec);
    for (key, value) in from_link(&link)? {
        draft.set_text(key, value);
    }

    // Без имени в ссылке — адрес.
    draft.name = link
        .name
        .clone()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| link.host.clone());

    Ok(draft)
}

/// Ссылка, разобранная на части.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// Схема без `://`, в нижнем регистре: `hy2`.
    pub scheme: String,
    /// Всё до `@`; границу имени и пароля знает только протокол (у Hysteria 2
    /// двоеточие часть пароля, у SOCKS5 — разделитель).
    pub userinfo: Option<String>,
    /// Хост без скобок, даже если это IPv6.
    pub host: String,
    /// Порт или диапазон портов, как он написан.
    pub port: Option<String>,
    /// Параметры запроса.
    pub query: Query,
    /// Имя после `#`, раскодированное.
    pub name: Option<String>,
}

impl Link {
    /// Адрес сервера для настроек; IPv6 в скобках, иначе порт не отделить.
    pub fn server(&self, default_port: u16) -> String {
        let port = self
            .port
            .clone()
            .unwrap_or_else(|| default_port.to_string());

        if self.host.contains(':') {
            format!("[{}]:{port}", self.host)
        } else {
            format!("{}:{port}", self.host)
        }
    }

    /// Пара `uuid:пароль` (TUIC, Juicity): первое двоеточие отделяет UUID,
    /// остальное — пароль целиком.
    pub fn uuid_password(&self) -> Result<(String, String), String> {
        let userinfo = self.userinfo();
        // Без пароля профиль не соберётся.
        let Some((uuid, password)) = userinfo.split_once(':') else {
            return Err(crate::i18n::s().link_no_password.to_owned());
        };
        if uuid.is_empty() {
            return Err(crate::i18n::s().link_no_uuid.to_owned());
        }
        if password.is_empty() {
            return Err(crate::i18n::s().link_no_password.to_owned());
        }
        Ok((uuid.to_owned(), password.to_owned()))
    }

    /// Userinfo, раскодированное как userinfo: проценты да, `+` нет.
    pub fn userinfo(&self) -> String {
        self.userinfo
            .as_deref()
            .map(str::trim)
            .map(percent_decode)
            .unwrap_or_default()
    }
}

/// Разбирает запись ссылки, не зная протокола.
pub fn split(raw: &str) -> Result<Link, String> {
    let raw = raw.trim();
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| crate::i18n::s().link_not_a_link.to_owned())?;

    // Сначала имя (`#`), потом запрос (`?`): иначе `#` в запросе уехал бы в параметры.
    let (rest, name) = split_once(rest, '#');
    let (authority, query) = split_once(rest, '?');

    // Пробелы из переносов мессенджера в адресе сделали бы сервер недоступным.
    let authority = authority.trim().trim_end_matches('/').trim();

    let (userinfo, host_port) = match authority.rsplit_once('@') {
        Some((userinfo, host)) => (Some(userinfo.to_owned()), host),
        None => (None, authority),
    };

    let (host, port) = split_host_port(host_port.trim())?;
    let host = host.trim();
    if host.is_empty() {
        return Err(crate::i18n::s().link_no_host.to_owned());
    }

    Ok(Link {
        scheme: scheme.trim().to_lowercase(),
        userinfo,
        host: host.to_owned(),
        port,
        query: Query::parse(query),
        name: name.map(decode_query),
    })
}

fn split_once(raw: &str, separator: char) -> (&str, Option<&str>) {
    match raw.split_once(separator) {
        Some((head, tail)) => (head, Some(tail)),
        None => (raw, None),
    }
}

/// Делит `host:port`, не путаясь в двоеточиях IPv6 (`[::1]:443`).
fn split_host_port(raw: &str) -> Result<(&str, Option<String>), String> {
    if let Some(rest) = raw.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| crate::i18n::s().link_bad_host.to_owned())?;
        let port = tail
            .trim()
            .strip_prefix(':')
            .map(|port| port.trim().to_owned());
        return Ok((host, port));
    }

    match raw.rsplit_once(':') {
        Some((host, port)) => Ok((host, Some(port.trim().to_owned()))),
        // Порт подставит протокол: у каждого свой.
        None => Ok((raw, None)),
    }
}

/// Параметры запроса.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query(Vec<(String, String)>);

impl Query {
    /// Разбирает `a=1&b=2`.
    fn parse(raw: Option<&str>) -> Self {
        let Some(raw) = raw else {
            return Self(Vec::new());
        };

        Self(
            raw.split('&')
                .filter(|pair| !pair.is_empty())
                .map(|pair| {
                    let (key, value) = split_once(pair, '=');
                    (
                        decode_query(key).to_lowercase(),
                        decode_query(value.unwrap_or_default()),
                    )
                })
                .collect(),
        )
    }

    /// Значение параметра, если оно непустое.
    pub fn get(&self, key: &str) -> Option<String> {
        let key = key.to_lowercase();
        self.0
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value.clone())
            .filter(|value| !value.is_empty())
    }

    /// Признак есть и означает «да»: `insecure=0` не снимает проверку сертификата.
    pub fn flag(&self, key: &str) -> bool {
        matches!(self.get(key).as_deref(), Some("1" | "true" | "yes" | "on"))
    }
}

/// Раскодирует часть запроса: проценты и `+` как пробел.
fn decode_query(raw: &str) -> String {
    percent_decode(&raw.replace('+', " "))
}

/// Заменяет `%XX` на байты; неверная последовательность остаётся как есть.
fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let pair = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or_default();
            if let Ok(byte) = u8::from_str_radix(pair, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "hy2://source:s3cret@example.net:3478\
                          ?sni=example.net&alpn=h3&insecure=0&allowInsecure=0#source";

    #[test]
    fn the_sample_link_parses_completely() {
        let draft = parse(SAMPLE).expect("ссылка разбирается");

        assert_eq!(draft.text("server"), "example.net:3478");
        // Двоеточие — часть пароля.
        assert_eq!(draft.text("password"), "source:s3cret");
        assert_eq!(draft.text("sni"), "example.net");
        assert_eq!(draft.name, "source");
        assert!(!draft.flag("insecure"), "`insecure=0` — это «проверять»");
    }

    #[test]
    fn the_sample_link_becomes_a_working_profile() {
        let profile = parse(SAMPLE)
            .expect("ссылка разбирается")
            .to_profile()
            .expect("профиль собирается");

        assert_eq!(profile.name, "source");
        assert_eq!(profile.outbound.protocol, "hysteria2");
        assert_eq!(
            profile.outbound.field("server").and_then(|v| v.as_str()),
            Some("example.net:3478")
        );
    }

    #[test]
    fn both_hysteria_schemes_work() {
        assert!(parse("hy2://pass@example.com:443").is_ok());
        assert!(parse("hysteria2://pass@example.com:443").is_ok());
        assert!(parse("HY2://pass@example.com:443").is_ok());
    }

    #[test]
    fn a_socks_link_parses() {
        let draft = parse("socks5://penguin:s3cret@127.0.0.1:1080#Дома").expect("разбирается");

        assert_eq!(draft.protocol(), "socks5");
        assert_eq!(draft.text("server"), "127.0.0.1:1080");
        // У SOCKS5 двоеточие — граница имени и пароля.
        assert_eq!(draft.text("username"), "penguin");
        assert_eq!(draft.text("password"), "s3cret");
        assert_eq!(draft.name, "Дома");
    }

    #[test]
    fn a_socks_link_without_a_password_is_fine() {
        let draft = parse("socks5://127.0.0.1:1080").expect("разбирается");
        assert!(draft.text("username").is_empty());
        assert_eq!(draft.name, "127.0.0.1");
        draft.to_profile().expect("профиль собирается");
    }

    #[test]
    fn a_missing_port_falls_back_to_the_usual_one_of_that_protocol() {
        assert_eq!(
            parse("hy2://pass@example.com")
                .expect("разбирается")
                .text("server"),
            "example.com:443"
        );
        assert_eq!(
            parse("socks5://example.com")
                .expect("разбирается")
                .text("server"),
            "example.com:1080"
        );
    }

    #[test]
    fn a_port_range_survives_as_written() {
        let draft = parse("hy2://pass@example.com:20000-30000").expect("разбирается");
        assert_eq!(draft.text("server"), "example.com:20000-30000");
    }

    #[test]
    fn an_ipv6_host_keeps_its_brackets() {
        let draft = parse("hy2://pass@[2001:db8::1]:443").expect("разбирается");
        assert_eq!(draft.text("server"), "[2001:db8::1]:443");
        draft.to_profile().expect("профиль собирается");
    }

    #[test]
    fn insecure_is_only_taken_as_yes_when_it_says_yes() {
        assert!(
            !parse("hy2://p@h.io?insecure=0")
                .expect("разбирается")
                .flag("insecure")
        );
        assert!(
            parse("hy2://p@h.io?insecure=1")
                .expect("разбирается")
                .flag("insecure")
        );
        assert!(
            parse("hy2://p@h.io?allowInsecure=1")
                .expect("разбирается")
                .flag("insecure")
        );
        assert!(!parse("hy2://p@h.io").expect("разбирается").flag("insecure"));
    }

    #[test]
    fn percent_encoded_values_are_decoded() {
        let draft = parse("hy2://%D0%BF%D0%B0%D1%80%D0%BE%D0%BB%D1%8C@h.io#%D0%94%D0%BE%D0%BC")
            .expect("разбирается");
        assert_eq!(draft.text("password"), "пароль");
        assert_eq!(draft.name, "Дом");
    }

    #[test]
    fn a_plus_means_a_space_in_the_query_and_a_plus_in_the_password() {
        let draft = parse("hy2://a+b@h.io?obfs-password=c+d").expect("разбирается");
        assert_eq!(draft.text("password"), "a+b");
        assert_eq!(draft.text("obfs"), "c d");
    }

    #[test]
    fn the_name_falls_back_to_the_host() {
        assert_eq!(
            parse("hy2://p@example.com").expect("разбирается").name,
            "example.com"
        );
        assert_eq!(
            parse("hy2://p@example.com#").expect("разбирается").name,
            "example.com"
        );
    }

    #[test]
    fn a_link_copied_across_lines_still_works() {
        let draft = parse(
            "hy2://source:s3cret@example.net:3478
 ?sni=example.net #source",
        )
        .expect("разбирается");

        assert_eq!(draft.text("server"), "example.net:3478");
        assert_eq!(draft.text("password"), "source:s3cret");
    }

    #[test]
    fn a_link_with_stray_spaces_parses() {
        let draft = parse("  hy2://pass@example.com:443  ").expect("разбирается");
        assert_eq!(draft.text("server"), "example.com:443");
    }

    #[test]
    fn a_hysteria_link_without_a_password_is_refused() {
        assert!(parse("hy2://example.com:443").is_err());
    }

    #[test]
    fn something_that_is_not_a_link_is_refused() {
        assert!(parse("просто текст").is_err());
        assert!(parse("ftp://example.com").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn recognising_a_link_does_not_need_it_to_be_valid() {
        assert!(looks_like_link("hy2://x"));
        assert!(looks_like_link("  HYSTERIA2://x  "));
        assert!(looks_like_link("socks5://x"));
        assert!(!looks_like_link("hy2://"));
        assert!(!looks_like_link("Дом"));
        assert!(!looks_like_link(""));
    }

    #[test]
    fn a_trailing_slash_is_allowed() {
        let draft = parse("hy2://p@example.com:443/?sni=a.io").expect("разбирается");
        assert_eq!(draft.text("server"), "example.com:443");
        assert_eq!(draft.text("sni"), "a.io");
    }

    #[test]
    fn a_link_to_a_bare_address_becomes_a_working_profile() {
        let profile = parse("hy2://root:s3cret@203.0.113.5:1984/?insecure=1")
            .expect("ссылка разбирается")
            .to_profile()
            .expect("профиль собирается");

        assert_eq!(profile.name, "203.0.113.5");
        assert_eq!(
            profile.outbound.field("server").and_then(|v| v.as_str()),
            Some("203.0.113.5:1984")
        );
    }

    #[test]
    fn a_hash_inside_the_query_does_not_eat_the_name() {
        let draft = parse("hy2://p@h.io?sni=a.io#Мой сервер").expect("разбирается");
        assert_eq!(draft.name, "Мой сервер");
        assert_eq!(draft.text("sni"), "a.io");
    }

    #[test]
    fn a_broken_percent_sequence_does_not_lose_the_link() {
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%ZZ"), "%ZZ");
        assert_eq!(percent_decode("a%20b"), "a b");
    }
}
