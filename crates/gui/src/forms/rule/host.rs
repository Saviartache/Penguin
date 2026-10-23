//! Запись в разделе адресов: вид по пометке и проверка при вводе.
//!
//! | Запись | Вид |
//! |---|---|
//! | `example.com` | домен и поддомены |
//! | `=example.com` | только этот домен |
//! | `*word*` | домены со словом |
//! | `.ru` | доменная зона |
//! | `RU` | страна по GeoIP |
//! | `10.0.0.0/8` | адрес или подсеть |
//!
//! Кириллица переводится в `xn--…` при вводе: правила сверяются с именем из SNI
//! и DNS, а оно всегда в ASCII.

use crate::forms::addresses::{self, Kind};
use crate::forms::punycode;

/// Вид записи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    /// `example.com` — домен и поддомены.
    Suffix,
    /// `=example.com` — только этот домен.
    Exact,
    /// `*word*` — домен, в котором есть слово.
    Keyword,
    /// Адрес или подсеть.
    Network,
    /// `.ru` — всё в доменной зоне.
    Zone,
    /// `RU` — адрес назначения в стране.
    Country,
}

/// Вид записи и значение без пометок; `None` — не адрес.
pub fn host_kind(value: &str) -> Option<(HostKind, &str)> {
    if let Some(name) = value.strip_prefix('=') {
        return (addresses::classify(name) == Some(Kind::Domain))
            .then_some((HostKind::Exact, name));
    }
    if let Some(word) = value
        .strip_prefix('*')
        .and_then(|rest| rest.strip_suffix('*'))
    {
        // Только ASCII: кириллическое слово не встретится в имени `xn--…`.
        let valid = !word.is_empty()
            && word
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
        return valid.then_some((HostKind::Keyword, word));
    }
    if let Some(zone) = value.strip_prefix('.').filter(|zone| is_label(zone)) {
        return Some((HostKind::Zone, zone));
    }
    if value.len() == 2 && value.bytes().all(|b| b.is_ascii_uppercase()) {
        return Some((HostKind::Country, value));
    }
    match addresses::classify(value) {
        Some(Kind::Domain) => Some((HostKind::Suffix, value)),
        Some(Kind::Network) => Some((HostKind::Network, value)),
        _ => None,
    }
}

/// Запись с пометкой, зона или страна — то, у чего не бывает порта.
/// `None` — обычный адрес; `Some(None)` — пометка есть, но запись неверна.
pub fn marked_host(token: &str) -> Option<Option<String>> {
    if token.len() == 2 && token.bytes().all(|b| b.is_ascii_alphabetic()) {
        let code = token.to_ascii_uppercase();
        return Some(crate::flags::Flag::of(&code).map(|_| code));
    }
    let zone = token
        .strip_prefix('.')
        .is_some_and(|rest| !rest.contains('.'));
    if !zone && !token.starts_with(['=', '*']) {
        return None;
    }
    let value = token.to_ascii_lowercase();
    Some(host_kind(&value).is_some().then_some(value))
}

/// Введённое в ASCII; пометка `=` или `.` перед именем сохраняется.
pub fn to_ascii(typed: &str) -> String {
    if typed.is_ascii() {
        return typed.to_owned();
    }
    let (mark, name) = match typed.strip_prefix(['=', '.']) {
        Some(name) => (&typed[..1], name),
        None => ("", typed),
    };
    punycode::to_ascii(name).map_or_else(|| typed.to_owned(), |name| format!("{mark}{name}"))
}

/// Метка зоны: буквы, цифры, дефис; не одни цифры.
fn is_label(zone: &str) -> bool {
    !zone.is_empty()
        && zone.len() <= 63
        && zone.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !zone.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_is_recognised_by_its_mark() {
        assert_eq!(
            host_kind("example.com"),
            Some((HostKind::Suffix, "example.com"))
        );
        assert_eq!(
            host_kind("=example.com"),
            Some((HostKind::Exact, "example.com"))
        );
        assert_eq!(host_kind("*google*"), Some((HostKind::Keyword, "google")));
        assert_eq!(host_kind(".ru"), Some((HostKind::Zone, "ru")));
        assert_eq!(host_kind(".xn--p1ai"), Some((HostKind::Zone, "xn--p1ai")));
        assert_eq!(host_kind("RU"), Some((HostKind::Country, "RU")));
        assert_eq!(
            host_kind("10.0.0.0/8"),
            Some((HostKind::Network, "10.0.0.0/8"))
        );
    }

    #[test]
    fn a_leading_dot_before_a_full_name_is_still_a_suffix() {
        assert_eq!(
            host_kind(".example.com"),
            Some((HostKind::Suffix, ".example.com"))
        );
    }

    #[test]
    fn broken_marks_are_not_hosts() {
        assert_eq!(host_kind("=nope"), None);
        assert_eq!(host_kind("*google"), None);
        assert_eq!(host_kind("*яндекс*"), None);
        assert_eq!(host_kind(".123"), None);
        assert_eq!(host_kind("."), None);
    }

    #[test]
    fn countries_are_checked_against_known_codes() {
        assert_eq!(marked_host("ru"), Some(Some("RU".to_owned())));
        assert_eq!(marked_host("De"), Some(Some("DE".to_owned())));
        assert_eq!(marked_host("QQ"), Some(None));
    }

    #[test]
    fn zones_and_marks_are_lowercased() {
        assert_eq!(marked_host(".RU"), Some(Some(".ru".to_owned())));
        assert_eq!(marked_host("=A.com"), Some(Some("=a.com".to_owned())));
        assert_eq!(marked_host(".a.com"), None);
        assert_eq!(marked_host("example.com"), None);
    }

    #[test]
    fn cyrillic_is_turned_into_ascii_keeping_the_mark() {
        assert_eq!(to_ascii(".рф"), ".xn--p1ai");
        assert_eq!(to_ascii("=яндекс.рф"), "=xn--d1acpjx3f.xn--p1ai");
        assert_eq!(to_ascii("яндекс.рф"), "xn--d1acpjx3f.xn--p1ai");
        assert_eq!(to_ascii("example.com"), "example.com");
    }
}
