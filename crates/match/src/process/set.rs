//! Набор процессов: точные пути в хеш-таблице, шаблоны — отдельным списком.
//!
//! Список выбранных приложений — самая частая и самая большая часть правил:
//! пользователь отмечает мышью два десятка программ, и все они попадают в одно
//! правило. Проверять их перебором значило бы платить двадцатью сравнениями
//! строк за каждое новое соединение.
//!
//! Поэтому точные пути и имена лежат в хеш-таблицах — проверка за один
//! просмотр, сколько бы записей ни было, — а перебираются только шаблоны и
//! префиксы, которых обычно единицы.

use crate::matcher::Matcher;
use crate::process::name::NameSet;
use crate::process::path::{GlobPathSet, PathSet, PrefixSet};
use crate::target::MatchTarget;

/// Приложения, отмеченные пользователем.
#[derive(Debug, Default)]
pub struct ProcessSet {
    paths: PathSet,
    names: NameSet,
    prefixes: PrefixSet,
    globs: Option<GlobPathSet>,
}

/// Сборщик набора.
#[derive(Debug, Default)]
pub struct ProcessSetBuilder {
    paths: Vec<String>,
    names: Vec<String>,
    prefixes: Vec<String>,
    globs: Vec<String>,
}

impl ProcessSetBuilder {
    /// Пустой сборщик.
    pub fn new() -> Self {
        Self::default()
    }

    /// Добавляет точные пути.
    pub fn paths<I: IntoIterator<Item = S>, S: AsRef<str>>(mut self, entries: I) -> Self {
        self.paths
            .extend(entries.into_iter().map(|e| e.as_ref().to_owned()));
        self
    }

    /// Добавляет имена файлов.
    pub fn names<I: IntoIterator<Item = S>, S: AsRef<str>>(mut self, entries: I) -> Self {
        self.names
            .extend(entries.into_iter().map(|e| e.as_ref().to_owned()));
        self
    }

    /// Добавляет каталоги.
    pub fn prefixes<I: IntoIterator<Item = S>, S: AsRef<str>>(mut self, entries: I) -> Self {
        self.prefixes
            .extend(entries.into_iter().map(|e| e.as_ref().to_owned()));
        self
    }

    /// Добавляет шаблоны.
    pub fn globs<I: IntoIterator<Item = S>, S: AsRef<str>>(mut self, entries: I) -> Self {
        self.globs
            .extend(entries.into_iter().map(|e| e.as_ref().to_owned()));
        self
    }

    /// Собирает набор.
    pub fn build(self) -> Result<ProcessSet, String> {
        let globs = if self.globs.is_empty() {
            None
        } else {
            Some(GlobPathSet::new(&self.globs)?)
        };

        Ok(ProcessSet {
            paths: PathSet::new(&self.paths),
            names: NameSet::new(&self.names),
            prefixes: PrefixSet::new(&self.prefixes),
            globs,
        })
    }
}

impl Matcher for ProcessSet {
    fn matches(&self, target: &MatchTarget<'_>) -> bool {
        // Порядок не случаен: дешёвые проверки впереди. Хеш-таблица отвечает
        // за один просмотр, перебор префиксов — за их число, шаблоны — дороже
        // всех.
        self.paths.matches(target)
            || self.names.matches(target)
            || self.prefixes.matches(target)
            || self
                .globs
                .as_ref()
                .is_some_and(|globs| globs.matches(target))
    }

    fn describe(&self) -> String {
        let mut parts = Vec::new();
        for (matcher, empty) in [
            (self.paths.describe(), self.paths.describe().ends_with("[]")),
            (self.names.describe(), self.names.describe().ends_with("[]")),
            (
                self.prefixes.describe(),
                self.prefixes.describe().ends_with("[]"),
            ),
        ] {
            if !empty {
                parts.push(matcher);
            }
        }
        if let Some(globs) = &self.globs {
            parts.push(globs.describe());
        }
        if parts.is_empty() {
            return "приложение не задано".to_owned();
        }
        format!("({})", parts.join(" или "))
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use penguin_core::network::Network;

    use super::*;

    fn target_for<'a>(path: &'a str, name: &'a str) -> MatchTarget<'a> {
        let destination: SocketAddr = "1.2.3.4:443".parse().expect("адрес");
        MatchTarget::to_address(Network::Tcp, destination).with_process(path, name)
    }

    #[test]
    fn any_kind_of_entry_matches() {
        let set = ProcessSetBuilder::new()
            .paths(["c:/apps/exact.exe"])
            .names(["byname.exe"])
            .prefixes(["c:/games"])
            .globs(["c:/tools/**/*.exe"])
            .build()
            .expect("собирается");

        assert!(set.matches(&target_for("c:/apps/exact.exe", "exact.exe")));
        assert!(set.matches(&target_for("d:/anywhere/byname.exe", "byname.exe")));
        assert!(set.matches(&target_for("c:/games/steam/steam.exe", "steam.exe")));
        assert!(set.matches(&target_for("c:/tools/a/b/tool.exe", "tool.exe")));
        assert!(!set.matches(&target_for("c:/work/other.exe", "other.exe")));
    }

    #[test]
    fn empty_set_matches_nothing() {
        let set = ProcessSetBuilder::new().build().expect("собирается");
        assert!(!set.matches(&target_for("c:/apps/app.exe", "app.exe")));
        assert_eq!(set.describe(), "приложение не задано");
    }

    #[test]
    fn broken_glob_fails_at_build_time() {
        // Ошибка должна прийти при сборке правил, а не на первом соединении.
        assert!(
            ProcessSetBuilder::new()
                .globs(["[unclosed"])
                .build()
                .is_err()
        );
    }
}
