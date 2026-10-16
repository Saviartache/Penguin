//! Путь к исполняемому файлу: точный, префикс каталога, glob.
//! Записи нормализуются тем же `normalize_path`, что и пути из системы.

use std::collections::HashSet;

use penguin_process::identity::normalize_path;

use super::glob::Glob;
use crate::matcher::Matcher;
use crate::target::MatchTarget;

/// Точные пути.
#[derive(Debug, Default)]
pub struct PathSet {
    paths: HashSet<String>,
}

/// Префиксы каталогов.
#[derive(Debug, Default)]
pub struct PrefixSet {
    prefixes: Vec<String>,
}

/// Шаблоны путей.
#[derive(Debug)]
pub struct GlobPathSet {
    globs: Vec<Glob>,
    labels: Vec<String>,
}

impl PathSet {
    /// Собирает набор точных путей.
    pub fn new<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            paths: entries
                .into_iter()
                .map(|e| normalize_path(e.as_ref()))
                .collect(),
        }
    }

    /// Совпадает ли путь.
    pub fn contains(&self, path: &str) -> bool {
        self.paths.contains(path)
    }
}

impl PrefixSet {
    /// Собирает набор префиксов; завершающий `/` добавляется, чтобы `c:/game` не ловил `c:/gamedev/`.
    pub fn new<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            prefixes: entries
                .into_iter()
                .map(|e| {
                    let prefix = normalize_path(e.as_ref());
                    if prefix.ends_with('/') {
                        prefix
                    } else {
                        format!("{prefix}/")
                    }
                })
                .collect(),
        }
    }

    /// Лежит ли путь под одним из префиксов.
    pub fn contains(&self, path: &str) -> bool {
        self.prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix.as_str()))
    }
}

impl GlobPathSet {
    /// Собирает набор шаблонов.
    pub fn new<I, S>(entries: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut globs = Vec::new();
        let mut labels = Vec::new();

        for entry in entries {
            let pattern = normalize_path(entry.as_ref());
            globs.push(
                Glob::new(&pattern)
                    .map_err(|e| format!("не разбирается шаблон `{pattern}`: {e}"))?,
            );
            labels.push(pattern);
        }
        Ok(Self { globs, labels })
    }

    /// Подходит ли путь под шаблон.
    pub fn matches_path(&self, path: &str) -> bool {
        self.globs.iter().any(|g| g.is_match(path))
    }
}

impl Matcher for PathSet {
    fn matches(&self, target: &MatchTarget<'_>) -> bool {
        target.process_path.is_some_and(|path| self.contains(path))
    }

    fn describe(&self) -> String {
        let mut sorted: Vec<&str> = self.paths.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        format!("путь в [{}]", sorted.join(", "))
    }
}

impl Matcher for PrefixSet {
    fn matches(&self, target: &MatchTarget<'_>) -> bool {
        target.process_path.is_some_and(|path| self.contains(path))
    }

    fn describe(&self) -> String {
        format!("путь начинается с [{}]", self.prefixes.join(", "))
    }
}

impl Matcher for GlobPathSet {
    fn matches(&self, target: &MatchTarget<'_>) -> bool {
        target
            .process_path
            .is_some_and(|path| self.matches_path(path))
    }

    fn describe(&self) -> String {
        format!("путь подходит под [{}]", self.labels.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    const APP: &str = "c:/program files/app/app.exe";
    #[cfg(not(windows))]
    const APP: &str = "/opt/app/app";

    #[test]
    fn exact_path_matches() {
        let set = PathSet::new([APP]);
        assert!(set.contains(APP));
        assert!(!set.contains("/somewhere/else"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_notation_is_normalized_on_both_sides() {
        let set = PathSet::new([r"C:\Program Files\App\App.exe"]);
        assert!(set.contains("c:/program files/app/app.exe"));
    }

    #[test]
    fn prefix_requires_a_separator() {
        let set = PrefixSet::new(["c:/games"]);
        assert!(set.contains("c:/games/steam/steam.exe"));
        assert!(!set.contains("c:/gamedev/tool.exe"));
    }

    #[test]
    fn prefix_accepts_trailing_separator() {
        let with = PrefixSet::new(["c:/games/"]);
        let without = PrefixSet::new(["c:/games"]);
        assert_eq!(with.prefixes, without.prefixes);
    }

    #[test]
    fn glob_matches_by_mask() {
        let set = GlobPathSet::new(["c:/games/**/*.exe"]).expect("собирается");
        assert!(set.matches_path("c:/games/steam/steam.exe"));
        assert!(set.matches_path("c:/games/a/b/c/game.exe"));
        assert!(!set.matches_path("c:/games/readme.txt"));
        assert!(!set.matches_path("c:/work/app.exe"));
    }

    #[test]
    fn glob_rejects_broken_patterns() {
        assert!(GlobPathSet::new(["c:/games/[unclosed"]).is_err());
    }

    #[test]
    fn unknown_owner_never_matches() {
        use std::net::SocketAddr;

        use penguin_core::network::Network;

        let destination: SocketAddr = "1.2.3.4:443".parse().expect("адрес");
        let target = MatchTarget::to_address(Network::Tcp, destination);
        assert!(!PathSet::new([APP]).matches(&target));
        assert!(!PrefixSet::new(["c:/"]).matches(&target));
    }
}
