//! Имя исполняемого файла без пути.
//!
//! Самый удобный для пользователя способ и самый небезопасный. `chrome.exe`
//! пишется в одну строку и не зависит от того, куда установлен браузер, — но
//! ровно так же называется любой файл, который кто-то положил рядом. Правило
//! «пустить `chrome.exe` мимо тоннеля» пустит мимо и его.
//!
//! Поэтому интерфейс предлагает путь, а имя оставляет как явный выбор.

use std::collections::HashSet;

use crate::matcher::Matcher;
use crate::target::MatchTarget;

/// Набор имён исполняемых файлов.
#[derive(Debug, Default)]
pub struct NameSet {
    names: HashSet<String>,
}

impl NameSet {
    /// Собирает набор.
    pub fn new<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            names: entries
                .into_iter()
                .map(|e| normalize_name(e.as_ref()))
                .collect(),
        }
    }

    /// Есть ли имя в наборе.
    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// Набор пуст.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// Приводит имя к виду, в котором его сравнивают.
///
/// На Windows регистр в именах файлов не значим, а пользователь пишет и
/// `Chrome.exe`, и `chrome.exe`. На остальных системах регистр значим, и
/// трогать его нельзя.
pub fn normalize_name(name: &str) -> String {
    #[cfg(windows)]
    {
        name.trim().to_lowercase()
    }
    #[cfg(not(windows))]
    {
        name.trim().to_owned()
    }
}

impl Matcher for NameSet {
    fn matches(&self, target: &MatchTarget<'_>) -> bool {
        target.process_name.is_some_and(|name| self.contains(name))
    }

    fn describe(&self) -> String {
        let mut sorted: Vec<&str> = self.names.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        format!("имя в [{}]", sorted.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_by_name() {
        let set = NameSet::new(["chrome.exe", "firefox.exe"]);
        assert!(set.contains("chrome.exe"));
        assert!(set.contains("firefox.exe"));
        assert!(!set.contains("edge.exe"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_names_ignore_case() {
        let set = NameSet::new(["Chrome.EXE"]);
        assert!(set.contains("chrome.exe"));
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_names_keep_case() {
        let set = NameSet::new(["Curl"]);
        assert!(!set.contains("curl"));
    }

    #[test]
    fn empty_set_matches_nothing() {
        assert!(NameSet::new(Vec::<&str>::new()).is_empty());
    }
}
