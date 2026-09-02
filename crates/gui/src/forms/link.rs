//! Разбор ссылки-приглашения Hysteria 2.
//!
//! ```text
//! hy2://source:s3cret@example.net:3478?sni=example.net&insecure=0#source
//! ```
//!
//! Ссылку присылают в мессенджере, и переносить из неё поля руками — семь
//! шансов ошибиться в пароле. Поэтому разбор здесь, а не «скопируйте адрес,
//! потом пароль».
//!
//! # Что здесь не как в обычном URL
//!
//! **Двоеточие в userinfo — часть пароля, а не разделитель.** У Hysteria 2
//! userinfo целиком и есть строка проверки подлинности: в примере выше пароль
//! — `source:s3cret`, а не пользователь `source` с паролем
//! `s3cret`. Разделить их значило бы молча отдать серверу половину
//! пароля.
//!
//! **`+` в запросе означает пробел, а в userinfo — плюс.** Ссылки делает
//! реализация на Go, а её `url.Query()` разбирает запрос как форму, где `+`
//! — это пробел; userinfo по тем же правилам разбирается иначе. Перепутать
//! означает испортить пароль обфускации.
//!
//! **Порт может быть диапазоном** (`host:20000-30000`) — это смена порта на
//! ходу. Он передаётся в настройки как есть: разбирать его умеет сам протокол.

use crate::forms::server::Draft;

/// Схемы, под которыми ходит одна и та же ссылка.
const SCHEMES: [&str; 2] = ["hysteria2://", "hy2://"];

/// Порт, если в ссылке его не указали.
const DEFAULT_PORT: u16 = 443;

/// Похожа ли строка на ссылку-приглашение.
///
/// Нужна, чтобы отличить «человек вставил ссылку» от «человек печатает имя»:
/// разбирать каждое нажатие клавиши и показывать ошибку на каждой букве —
/// худший способ помочь.
pub fn looks_like_link(raw: &str) -> bool {
    let raw = raw.trim();
    SCHEMES
        .iter()
        .any(|scheme| raw.len() > scheme.len() && raw.to_lowercase().starts_with(scheme))
}

/// Разбирает ссылку в черновик профиля.
///
/// `Err` — текст, который можно показать как есть: разбирать код ошибки в
/// интерфейсе всё равно некому.
pub fn parse(raw: &str) -> Result<Draft, String> {
    let raw = raw.trim();

    let rest = SCHEMES
        .iter()
        .find_map(|scheme| {
            raw.get(..scheme.len())
                .filter(|head| head.eq_ignore_ascii_case(scheme))
                .map(|_| &raw[scheme.len()..])
        })
        .ok_or_else(|| crate::i18n::s().link_not_a_link.to_owned())?;

    // Порядок разбора: сначала имя (после `#`), потом запрос (после `?`), и
    // только оставшееся — адрес. Иначе `#` внутри запроса уехал бы в параметры.
    let (rest, name) = split_once(rest, '#');
    let (authority, query) = split_once(rest, '?');

    // Косая черта после адреса допустима и ничего не значит. Пробелы —
    // тоже: ссылку копируют из мессенджера, где она переносится по строкам, и
    // невидимый пробел в адресе означает сервер, к которому не подключиться.
    let authority = authority.trim().trim_end_matches('/').trim();

    let (auth, host_port) = match authority.rsplit_once('@') {
        Some((auth, host)) => (Some(auth), host),
        None => (None, authority),
    };

    let (host, port) = split_host_port(host_port.trim())?;
    let host = host.trim();
    if host.is_empty() {
        return Err(crate::i18n::s().link_no_host.to_owned());
    }

    let params = Query::parse(query);

    let mut draft = Draft {
        server: format!("{host}:{port}"),
        // Пароль — весь userinfo целиком, вместе с двоеточиями.
        password: auth.map(str::trim).map(decode_userinfo).unwrap_or_default(),
        sni: params.get("sni").unwrap_or_default(),
        obfs: params.get("obfs-password").unwrap_or_default(),
        // `insecure` и `allowInsecure` встречаются оба; достаточно одного.
        insecure: params.flag("insecure") || params.flag("allowInsecure"),
        ..Draft::default()
    };

    // Имя из ссылки, а если его нет — адрес: безымянный профиль неотличим в
    // списке от соседнего.
    draft.name = name
        .map(decode_query)
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| host.to_owned());

    if draft.password.is_empty() {
        return Err(crate::i18n::s().link_no_password.to_owned());
    }

    // `alpn` в ссылке встречается, но в настройках его нет: Hysteria 2 ходит
    // только по `h3`, и хранить единственное возможное значение незачем.
    Ok(draft)
}

/// Делит строку по первому вхождению разделителя.
fn split_once(raw: &str, separator: char) -> (&str, Option<&str>) {
    match raw.split_once(separator) {
        Some((head, tail)) => (head, Some(tail)),
        None => (raw, None),
    }
}

/// Разделяет `host:port`, не путаясь в двоеточиях IPv6.
fn split_host_port(raw: &str) -> Result<(&str, String), String> {
    // IPv6 в скобках: `[::1]:443`. Без этого разбора двоеточия адреса приняли
    // бы за разделитель порта.
    if let Some(rest) = raw.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| crate::i18n::s().link_bad_host.to_owned())?;
        let port = tail
            .trim()
            .strip_prefix(':')
            .map_or_else(|| DEFAULT_PORT.to_string(), |port| port.trim().to_owned());
        return Ok((host, port));
    }

    match raw.rsplit_once(':') {
        Some((host, port)) => Ok((host, port.trim().to_owned())),
        // Порт не указан — берётся тот, на котором Hysteria 2 работает чаще
        // всего.
        None => Ok((raw, DEFAULT_PORT.to_string())),
    }
}

/// Параметры запроса.
struct Query(Vec<(String, String)>);

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
    fn get(&self, key: &str) -> Option<String> {
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
    fn flag(&self, key: &str) -> bool {
        matches!(self.get(key).as_deref(), Some("1" | "true" | "yes" | "on"))
    }
}

/// Раскодирует userinfo: только проценты, `+` остаётся плюсом.
fn decode_userinfo(raw: &str) -> String {
    percent_decode(raw)
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

        assert_eq!(draft.server, "example.net:3478");
        // Двоеточие — часть пароля, а не разделитель: половина пароля на
        // сервере не подойдёт.
        assert_eq!(draft.password, "source:s3cret");
        assert_eq!(draft.sni, "example.net");
        assert_eq!(draft.name, "source");
        assert!(!draft.insecure, "`insecure=0` — это «проверять»");
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
        assert_eq!(
            profile.outbound.field("server").and_then(|v| v.as_str()),
            Some("example.net:3478")
        );
    }

    #[test]
    fn both_schemes_work() {
        assert!(parse("hy2://pass@example.com:443").is_ok());
        assert!(parse("hysteria2://pass@example.com:443").is_ok());
        // Регистр схемы значения не имеет: ссылку могли переписать руками.
        assert!(parse("HY2://pass@example.com:443").is_ok());
    }

    #[test]
    fn a_missing_port_falls_back_to_the_usual_one() {
        let draft = parse("hy2://pass@example.com").expect("разбирается");
        assert_eq!(draft.server, "example.com:443");
    }

    #[test]
    fn a_port_range_survives_as_written() {
        // Диапазон — это смена порта на ходу; разбирать его умеет протокол.
        let draft = parse("hy2://pass@example.com:20000-30000").expect("разбирается");
        assert_eq!(draft.server, "example.com:20000-30000");
    }

    #[test]
    fn an_ipv6_host_keeps_its_brackets_apart_from_the_port() {
        let draft = parse("hy2://pass@[2001:db8::1]:443").expect("разбирается");
        assert_eq!(draft.server, "2001:db8::1:443");
    }

    #[test]
    fn insecure_is_only_taken_as_yes_when_it_says_yes() {
        // Прочитать наличие параметра как согласие значило бы молча снять
        // единственную защиту от подмены сервера.
        assert!(
            !parse("hy2://p@h.io?insecure=0")
                .expect("разбирается")
                .insecure
        );
        assert!(
            parse("hy2://p@h.io?insecure=1")
                .expect("разбирается")
                .insecure
        );
        assert!(
            parse("hy2://p@h.io?allowInsecure=1")
                .expect("разбирается")
                .insecure
        );
        assert!(!parse("hy2://p@h.io").expect("разбирается").insecure);
    }

    #[test]
    fn percent_encoded_values_are_decoded() {
        let draft = parse("hy2://%D0%BF%D0%B0%D1%80%D0%BE%D0%BB%D1%8C@h.io#%D0%94%D0%BE%D0%BC")
            .expect("разбирается");
        assert_eq!(draft.password, "пароль");
        assert_eq!(draft.name, "Дом");
    }

    #[test]
    fn a_plus_means_a_space_in_the_query_and_a_plus_in_the_password() {
        // Ссылки делает реализация на Go: её `url.Query()` разбирает запрос
        // как форму, а userinfo — нет.
        let draft = parse("hy2://a+b@h.io?obfs-password=c+d").expect("разбирается");
        assert_eq!(draft.password, "a+b");
        assert_eq!(draft.obfs, "c d");
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

        assert_eq!(draft.server, "example.net:3478");
        assert_eq!(draft.password, "source:s3cret");
    }

    #[test]
    fn a_link_with_stray_spaces_parses() {
        let draft = parse("  hy2://pass@example.com:443  ").expect("разбирается");
        assert_eq!(draft.server, "example.com:443");
    }

    #[test]
    fn a_link_without_a_password_is_refused() {
        // Профиль без пароля не подключится, и узнать об этом лучше сразу.
        assert!(parse("hy2://example.com:443").is_err());
    }

    #[test]
    fn something_that_is_not_a_link_is_refused() {
        assert!(parse("просто текст").is_err());
        assert!(parse("https://example.com").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn recognising_a_link_does_not_need_it_to_be_valid() {
        // Признак нужен, чтобы отличить вставленную ссылку от набираемого
        // имени, а не чтобы проверить её.
        assert!(looks_like_link("hy2://x"));
        assert!(looks_like_link("  HYSTERIA2://x  "));
        assert!(!looks_like_link("hy2://"));
        assert!(!looks_like_link("Дом"));
        assert!(!looks_like_link(""));
    }

    #[test]
    fn a_trailing_slash_is_allowed() {
        let draft = parse("hy2://p@example.com:443/?sni=a.io").expect("разбирается");
        assert_eq!(draft.server, "example.com:443");
        assert_eq!(draft.sni, "a.io");
    }

    #[test]
    fn a_hash_inside_the_query_does_not_eat_the_name() {
        // Имя отделяется первым `#`, и только потом разбирается запрос.
        let draft = parse("hy2://p@h.io?sni=a.io#Мой сервер").expect("разбирается");
        assert_eq!(draft.name, "Мой сервер");
        assert_eq!(draft.sni, "a.io");
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
