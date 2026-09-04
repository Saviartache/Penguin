//! Разбор ссылки-приглашения.
//!
//! ```text
//! hy2://source:s3cret@example.net:3478?sni=example.net&insecure=0#source
//! socks5://penguin:s3cret@127.0.0.1:1080#Дома
//! ```
//!
//! Ссылку присылают в мессенджере, и переносить из неё поля руками — семь
//! шансов ошибиться в пароле. Поэтому разбор здесь, а не «скопируйте адрес,
//! потом пароль».
//!
//! # Что здесь общее, а что — протокола
//!
//! Общее — разбор самой записи: схема, userinfo, адрес, запрос, имя после
//! `#`. Он одинаков у всех, кто пишет ссылки, и живёт здесь.
//!
//! Своё у протокола — что из разобранного куда положить: у Hysteria 2
//! userinfo целиком и есть пароль, у SOCKS5 это `имя:пароль` через двоеточие.
//! Это описывает [`crate::forms::protocol::ProtocolSpec::from_link`], и
//! новый протокол добавляется вместе со своими ссылками, не трогая этот файл.
//!
//! # Что здесь не как в обычном URL
//!
//! **`+` в запросе означает пробел, а в userinfo — плюс.** Ссылки делает
//! реализация на Go, а её `url.Query()` разбирает запрос как форму, где `+`
//! — это пробел; userinfo по тем же правилам разбирается иначе. Перепутать
//! означает испортить пароль обфускации.
//!
//! **Порт может быть диапазоном** (`host:20000-30000`) — это смена порта на
//! ходу. Он передаётся в настройки как есть: разбирать его умеет сам протокол.

use crate::forms::protocol;
use crate::forms::server::Draft;

/// Похожа ли строка на ссылку-приглашение.
///
/// Нужна, чтобы отличить «человек вставил ссылку» от «человек печатает имя»:
/// разбирать каждое нажатие клавиши и показывать ошибку на каждой букве —
/// худший способ помочь.
pub fn looks_like_link(raw: &str) -> bool {
    let raw = raw.trim().to_lowercase();
    protocol::ALL
        .iter()
        .flat_map(|spec| spec.schemes)
        .any(|scheme| raw.len() > scheme.len() && raw.starts_with(scheme))
}

/// Разбирает ссылку в черновик профиля.
///
/// `Err` — текст, который можно показать как есть: разбирать код ошибки в
/// интерфейсе всё равно некому.
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

    // Имя из ссылки, а если его нет — адрес: безымянный профиль неотличим в
    // списке от соседнего.
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
    /// Всё до `@`, как оно написано.
    ///
    /// Не разделено на имя и пароль намеренно: где здесь разделитель, знает
    /// только протокол. У Hysteria 2 двоеточие — часть пароля, у SOCKS5 —
    /// граница между именем и паролем, и разделить это здесь значило бы
    /// молча отдать серверу половину пароля.
    pub userinfo: Option<String>,
    /// Хост без скобок, даже если это IPv6.
    pub host: String,
    /// Порт или диапазон портов, как он написан.
    pub port: Option<String>,
    /// Параметры запроса.
    pub query: Query,
    /// Имя после `#`, уже раскодированное.
    pub name: Option<String>,
}

impl Link {
    /// Адрес сервера в том виде, в каком он ложится в настройки.
    ///
    /// IPv6 берётся обратно в скобки: без них `2001:db8::1:443` — это
    /// законный адрес IPv6 сам по себе, и где в нём порт, не знает никто.
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

    // Порядок разбора: сначала имя (после `#`), потом запрос (после `?`), и
    // только оставшееся — адрес. Иначе `#` внутри запроса уехал бы в параметры.
    let (rest, name) = split_once(rest, '#');
    let (authority, query) = split_once(rest, '?');

    // Косая черта после адреса допустима и ничего не значит. Пробелы —
    // тоже: ссылку копируют из мессенджера, где она переносится по строкам, и
    // невидимый пробел в адресе означает сервер, к которому не подключиться.
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

/// Делит строку по первому вхождению разделителя.
fn split_once(raw: &str, separator: char) -> (&str, Option<&str>) {
    match raw.split_once(separator) {
        Some((head, tail)) => (head, Some(tail)),
        None => (raw, None),
    }
}

/// Разделяет `host:port`, не путаясь в двоеточиях IPv6.
fn split_host_port(raw: &str) -> Result<(&str, Option<String>), String> {
    // IPv6 в скобках: `[::1]:443`. Без этого разбора двоеточия адреса приняли
    // бы за разделитель порта.
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
        // Порт не указан — его подставит протокол: у каждого он свой.
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
        self.0
            .iter()
            .find(|(name, _)| name == &key.to_lowercase())
            .map(|(_, value)| value.clone())
            .filter(|value| !value.is_empty())
    }

    /// Признак: есть и означает «да».
    ///
    /// `insecure=0` — это **не** «не проверять сертификат». Прочитать наличие
    /// параметра как согласие значило бы молча снять единственную защиту от
    /// подмены сервера.
    pub fn flag(&self, key: &str) -> bool {
        matches!(self.get(key).as_deref(), Some("1" | "true" | "yes" | "on"))
    }
}

/// Раскодирует часть запроса: проценты и `+` как пробел.
fn decode_query(raw: &str) -> String {
    percent_decode(&raw.replace('+', " "))
}

/// Заменяет `%XX` на байты и собирает строку.
///
/// Незавершённая или неверная последовательность оставляется как есть:
/// ссылка, набранная руками, чаще содержит лишний процент, чем требует
/// отказа целиком.
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

    /// Ссылка из задачи — та, ради которой всё и затевалось.
    const SAMPLE: &str = "hy2://source:s3cret@example.net:3478\
                          ?sni=example.net&alpn=h3&insecure=0&allowInsecure=0#source";

    #[test]
    fn the_sample_link_parses_completely() {
        let draft = parse(SAMPLE).expect("ссылка разбирается");

        assert_eq!(draft.text("server"), "example.net:3478");
        // Двоеточие — часть пароля, а не разделитель: половина пароля на
        // сервере не подойдёт.
        assert_eq!(draft.text("password"), "source:s3cret");
        assert_eq!(draft.text("sni"), "example.net");
        assert_eq!(draft.name, "source");
        assert!(!draft.flag("insecure"), "`insecure=0` — это «проверять»");
    }

    #[test]
    fn the_sample_link_becomes_a_working_profile() {
        // Разобраться мало: из черновика обязан собраться профиль, иначе
        // импорт даёт форму, которую всё равно нельзя сохранить.
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
        // Регистр схемы значения не имеет: ссылку могли переписать руками.
        assert!(parse("HY2://pass@example.com:443").is_ok());
    }

    #[test]
    fn a_socks_link_parses() {
        let draft = parse("socks5://penguin:s3cret@127.0.0.1:1080#Дома").expect("разбирается");

        assert_eq!(draft.protocol(), "socks5");
        assert_eq!(draft.text("server"), "127.0.0.1:1080");
        // У SOCKS5 двоеточие — граница имени и пароля, а не часть пароля.
        assert_eq!(draft.text("username"), "penguin");
        assert_eq!(draft.text("password"), "s3cret");
        assert_eq!(draft.name, "Дома");
    }

    #[test]
    fn a_socks_link_without_a_password_is_fine() {
        // Прокси без пароля — обычное дело: `ssh -D` поднимает именно такой.
        let draft = parse("socks5://127.0.0.1:1080").expect("разбирается");
        assert!(draft.text("username").is_empty());
        assert_eq!(draft.name, "127.0.0.1");
        draft.to_profile().expect("профиль собирается");
    }

    #[test]
    fn an_http_proxy_link_parses_under_both_schemes() {
        let draft = parse("http://proxy.example.com:8080").expect("разбирается");
        assert_eq!(draft.protocol(), "http");

        let draft = parse("https://user:pass@proxy.example.com:8443").expect("разбирается");
        assert_eq!(draft.protocol(), "https");
        assert_eq!(draft.text("username"), "user");
        assert_eq!(draft.text("password"), "pass");
    }

    #[test]
    fn a_missing_port_falls_back_to_the_usual_one_of_that_protocol() {
        // У каждого протокола он свой, и общего умолчания тут быть не может.
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
    fn a_web_address_is_not_taken_for_a_proxy() {
        // `http://` и `https://` — это ещё и любая ссылка на страницу, и
        // вставляют их сюда чаще по ошибке, чем нарочно. Отличает их порт: у
        // прокси он написан почти всегда, у страницы — почти никогда.
        let reason = parse("https://example.com").expect_err("это не прокси");
        assert_eq!(reason, crate::i18n::s().link_no_port);

        parse("https://example.com:8443").expect("а это прокси");
    }

    #[test]
    fn a_port_range_survives_as_written() {
        // Диапазон — это смена порта на ходу; разбирать его умеет протокол.
        let draft = parse("hy2://pass@example.com:20000-30000").expect("разбирается");
        assert_eq!(draft.text("server"), "example.com:20000-30000");
    }

    #[test]
    fn an_ipv6_host_keeps_its_brackets() {
        // Без скобок `2001:db8::1:443` — это законный адрес IPv6 сам по себе,
        // и где в нём порт, не знает никто.
        let draft = parse("hy2://pass@[2001:db8::1]:443").expect("разбирается");
        assert_eq!(draft.text("server"), "[2001:db8::1]:443");
        draft.to_profile().expect("профиль собирается");
    }

    #[test]
    fn insecure_is_only_taken_as_yes_when_it_says_yes() {
        // Прочитать наличие параметра как согласие значило бы молча снять
        // единственную защиту от подмены сервера.
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
        // Ссылки делает реализация на Go: её `url.Query()` разбирает запрос
        // как форму, а userinfo — нет.
        let draft = parse("hy2://a+b@h.io?obfs-password=c+d").expect("разбирается");
        assert_eq!(draft.text("password"), "a+b");
        assert_eq!(draft.text("obfs"), "c d");
    }

    #[test]
    fn the_name_falls_back_to_the_host() {
        // Безымянный профиль неотличим в списке от соседнего.
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
        // Мессенджер переносит длинную ссылку, и вставляется она с пробелами.
        // Невидимый пробел в адресе — это сервер, к которому не подключиться.
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
        // Профиль без пароля не подключится, и узнать об этом лучше сразу.
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
        // Признак нужен, чтобы отличить вставленную ссылку от набираемого
        // имени, а не чтобы проверить её.
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
        // Сервер по адресу, без `sni` и без имени: такие ссылки раздают как
        // есть, и профиль из них обязан собираться.
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
        // Имя отделяется первым `#`, и только потом разбирается запрос.
        let draft = parse("hy2://p@h.io?sni=a.io#Мой сервер").expect("разбирается");
        assert_eq!(draft.name, "Мой сервер");
        assert_eq!(draft.text("sni"), "a.io");
    }

    #[test]
    fn a_broken_percent_sequence_does_not_lose_the_link() {
        // Ссылка, набранная руками, чаще содержит лишний процент, чем требует
        // отказа целиком.
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%ZZ"), "%ZZ");
        assert_eq!(percent_decode("a%20b"), "a b");
    }
}
