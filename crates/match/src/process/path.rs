//! Путь к исполняемому файлу: точный, префикс, glob. С нормализацией регистра
//! и разделителей.
//!
//! Три способа задать приложение, от точного к общему:
//!
//! | Способ | Запись | Что ловит |
//! |---|---|---|
//! | точный путь | `c:/program files/app/app.exe` | ровно этот файл |
//! | префикс | `c:/games/` | всё внутри каталога |
//! | шаблон | `c:/games/**/*.exe` | по маске |
//!
//! Пути приходят уже нормализованными (`penguin_process::identity`), и
//! записи пользователя нормализуются здесь тем же способом — иначе
//! `C:\Games\` из настроек не совпало бы с `c:/games/` из системы.

use std::collections::HashSet;

use globset::{Glob, GlobSet, GlobSetBuilder};
use penguin_process::identity::normalize_path;

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
    globs: GlobSet,
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
    /// Собирает набор префиксов.
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
                    // Разделитель в конце обязателен: без него `c:/game`
                    // поймало бы и `c:/gamedev/`, чего пользователь не имел
                    // в виду.
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
        let mut builder = GlobSetBuilder::new();
        let mut labels = Vec::new();

        for entry in entries {
            let pattern = normalize_path(entry.as_ref());
            let glob = Glob::new(&pattern)
                .map_err(|e| format!("не разбирается шаблон `{pattern}`: {e}"))?;
            builder.add(glob);
            labels.push(pattern);
        }

        let globs = builder
            .build()
            .map_err(|e| format!("не удалось собрать шаблоны: {e}"))?;
        Ok(Self { globs, labels })
    }

    /// Подходит ли путь под шаблон.
    pub fn matches_path(&self, path: &str) -> bool {
        self.globs.is_match(path)
    }
}

impl Matcher for PathSet {
    fn matches(&self, target: &MatchTarget<'_>) -> bool {
        // Владелец неизвестен — правило по приложению не применяется.
        // «Не знаю чьё» и «ничьё» — разные вещи, и молча блокировать первое
        // нельзя.
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
        // Пользователь копирует путь из проводника — с обратными слэшами и
        // заглавными буквами. Система выдаёт его иначе. Совпасть обязаны.
        let set = PathSet::new([r"C:\Program Files\App\App.exe"]);
        assert!(set.contains("c:/program files/app/app.exe"));
    }

    #[test]
    fn prefix_requires_a_separator() {
        // Без завершающего разделителя `c:/game` поймало бы `c:/gamedev/`.
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
        // Короткое соединение могло закрыться раньше, чем мы успели заглянуть
        // в таблицу. Такое уходит по умолчанию режима, а не блокируется.
        assert!(!PathSet::new([APP]).matches(&target));
        assert!(!PrefixSet::new(["c:/"]).matches(&target));
    }
}
