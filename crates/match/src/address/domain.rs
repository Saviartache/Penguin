//! Домены: точное совпадение, суффикс, подстрока, регулярное выражение.
//!
//! Четыре вида, и они не взаимозаменяемы:
//!
//! | Вид | `youtube.com` | `www.youtube.com` | `notyoutube.com` |
//! |---|---|---|---|
//! | точно `youtube.com` | ✓ | — | — |
//! | суффикс `youtube.com` | ✓ | ✓ | — |
//! | подстрока `youtube` | ✓ | ✓ | ✓ |
//!
//! Разница между суффиксом и подстрокой — самая важная. Суффикс проверяет
//! **границу метки**: `youtube.com` совпадает с `www.youtube.com`, но не с
//! `notyoutube.com`, потому что перед совпавшим хвостом стоит точка. Наивная
//! проверка `ends_with` этого не даёт, и правило «весь YouTube в тоннель»
//! утащило бы туда чужой сайт с похожим именем.
//!
//! Точные имена и суффиксы ищутся хеш-таблицами, подстроки — автоматом
//! Ахо — Корасик за один проход по имени, сколько бы подстрок ни задали.

use std::collections::HashSet;

use aho_corasick::AhoCorasick;
use penguin_core::address::normalize_domain;
use regex::RegexSet;

use crate::matcher::Matcher;
use crate::target::MatchTarget;

/// Набор доменных условий одного вида.
#[derive(Debug)]
pub enum DomainSet {
    /// Точное совпадение имени.
    Exact(HashSet<String>),
    /// Имя или любой его поддомен.
    Suffix(HashSet<String>),
    /// Подстрока в имени.
    Keyword(Box<KeywordSet>),
    /// Регулярное выражение.
    Regex(Box<RegexMatcher>),
}

/// Подстроки, свёрнутые в один автомат.
#[derive(Debug)]
pub struct KeywordSet {
    automaton: AhoCorasick,
    labels: Vec<String>,
}

/// Регулярные выражения, скомпилированные разом.
#[derive(Debug)]
pub struct RegexMatcher {
    set: RegexSet,
    labels: Vec<String>,
}

impl DomainSet {
    /// Точные имена.
    pub fn exact<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::Exact(
            entries
                .into_iter()
                .map(|e| normalize_domain(e.as_ref()))
                .collect(),
        )
    }

    /// Имена вместе с поддоменами.
    pub fn suffix<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::Suffix(
            entries
                .into_iter()
                // Ведущая точка в записи (`.example.com`) встречается в чужих
                // конфигурациях и означает ровно то же самое.
                .map(|e| normalize_domain(e.as_ref().trim_start_matches('.')))
                .collect(),
        )
    }

    /// Подстроки.
    pub fn keyword<I, S>(entries: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let labels: Vec<String> = entries
            .into_iter()
            .map(|e| e.as_ref().to_ascii_lowercase())
            .collect();
        let automaton = AhoCorasick::new(&labels)
            .map_err(|e| format!("не удалось собрать поиск подстрок: {e}"))?;
        Ok(Self::Keyword(Box::new(KeywordSet { automaton, labels })))
    }

    /// Регулярные выражения.
    pub fn regex<I, S>(entries: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let labels: Vec<String> = entries.into_iter().map(|e| e.as_ref().to_owned()).collect();
        let set = RegexSet::new(&labels)
            .map_err(|e| format!("не разбирается регулярное выражение: {e}"))?;
        Ok(Self::Regex(Box::new(RegexMatcher { set, labels })))
    }

    /// Подходит ли имя.
    pub fn matches_domain(&self, domain: &str) -> bool {
        match self {
            Self::Exact(names) => names.contains(domain),
            Self::Suffix(names) => {
                // Само имя и каждая его родительская метка. Так проверка
                // стоит числа точек в имени, а не числа записей в наборе.
                if names.contains(domain) {
                    return true;
                }
                let mut rest = domain;
                while let Some((_, parent)) = rest.split_once('.') {
                    if names.contains(parent) {
                        return true;
                    }
                    rest = parent;
                }
                false
            }
            Self::Keyword(set) => set.automaton.is_match(domain),
            Self::Regex(matcher) => matcher.set.is_match(domain),
        }
    }
}

impl Matcher for DomainSet {
    fn matches(&self, target: &MatchTarget<'_>) -> bool {
        // Имени может не быть вовсе: приложение разрешило его заранее и пошло
        // по адресу. Такое соединение доменному правилу не подходит — и это
        // верно, а не досадно: подставлять сюда обратное разрешение адреса
        // значило бы гадать.
        target
            .domain
            .is_some_and(|domain| self.matches_domain(domain))
    }

    fn describe(&self) -> String {
        match self {
            Self::Exact(names) => format!("домен в [{}]", joined(names)),
            Self::Suffix(names) => format!("домен оканчивается на [{}]", joined(names)),
            Self::Keyword(set) => format!("домен содержит [{}]", set.labels.join(", ")),
            Self::Regex(matcher) => format!("домен подходит под [{}]", matcher.labels.join(", ")),
        }
    }
}

fn joined(names: &HashSet<String>) -> String {
    let mut sorted: Vec<&str> = names.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    sorted.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_matches_only_itself() {
        let set = DomainSet::exact(["youtube.com"]);
        assert!(set.matches_domain("youtube.com"));
        assert!(!set.matches_domain("www.youtube.com"));
        assert!(!set.matches_domain("notyoutube.com"));
    }

    #[test]
    fn suffix_respects_label_boundaries() {
        // Главная тонкость всего файла: наивный `ends_with` утащил бы в
        // тоннель чужой сайт с похожим именем.
        let set = DomainSet::suffix(["youtube.com"]);
        assert!(set.matches_domain("youtube.com"));
        assert!(set.matches_domain("www.youtube.com"));
        assert!(set.matches_domain("a.b.c.youtube.com"));
        assert!(!set.matches_domain("notyoutube.com"));
        assert!(!set.matches_domain("youtube.com.evil.net"));
    }

    #[test]
    fn suffix_accepts_leading_dot_notation() {
        let set = DomainSet::suffix([".example.com"]);
        assert!(set.matches_domain("www.example.com"));
        assert!(set.matches_domain("example.com"));
    }

    #[test]
    fn keyword_matches_anywhere() {
        let set = DomainSet::keyword(["youtube"]).expect("собирается");
        assert!(set.matches_domain("youtube.com"));
        assert!(set.matches_domain("notyoutube.com"));
        assert!(set.matches_domain("m.youtube-nocookie.com"));
        assert!(!set.matches_domain("example.com"));
    }

    #[test]
    fn regex_works() {
        let set = DomainSet::regex([r"^ads?\d*\."]).expect("собирается");
        assert!(set.matches_domain("ad1.example.com"));
        assert!(set.matches_domain("ads.example.com"));
        assert!(!set.matches_domain("example.com"));
    }

    #[test]
    fn rejects_broken_regex() {
        assert!(DomainSet::regex(["(unclosed"]).is_err());
    }

    #[test]
    fn matching_is_case_insensitive() {
        let set = DomainSet::suffix(["YouTube.COM"]);
        // Имена нормализуются при создании набора, а на вход всегда приходит
        // уже нормализованное имя — см. `penguin_core::address`.
        assert!(set.matches_domain("www.youtube.com"));
    }

    #[test]
    fn connection_without_a_domain_never_matches() {
        use std::net::SocketAddr;

        use penguin_core::network::Network;

        let set = DomainSet::suffix(["youtube.com"]);
        let destination: SocketAddr = "1.2.3.4:443".parse().expect("адрес");
        let target = MatchTarget::to_address(Network::Tcp, destination);
        assert!(!set.matches(&target));
    }
}
