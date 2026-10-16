//! Статические записи, свои и из системного `hosts`; отвечают раньше всех остальных.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

use penguin_core::address::normalize_domain;

/// Статические соответствия имён и адресов.
#[derive(Debug, Default)]
pub struct Hosts {
    entries: HashMap<String, Vec<IpAddr>>,
}

impl Hosts {
    /// Пустой набор.
    pub fn new() -> Self {
        Self::default()
    }

    /// Набор из настроек.
    pub fn from_config(entries: &std::collections::BTreeMap<String, IpAddr>) -> Self {
        let mut hosts = Self::new();
        for (name, address) in entries {
            hosts.add(name, *address);
        }
        hosts
    }

    /// Добавляет запись.
    pub fn add(&mut self, name: &str, address: IpAddr) {
        self.entries
            .entry(normalize_domain(name))
            .or_default()
            .push(address);
    }

    /// Адреса имени.
    pub fn lookup(&self, name: &str) -> Option<&[IpAddr]> {
        self.entries.get(name).map(Vec::as_slice)
    }

    /// Записей нет.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Сколько имён описано.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Дочитывает системный файл `hosts`; ошибка чтения своих записей не отменяет.
    pub fn merge_system(&mut self) {
        let Some(path) = system_hosts_path() else {
            return;
        };
        let Ok(contents) = std::fs::read_to_string(&path) else {
            tracing::debug!(path = %path.display(), "системный hosts не прочитан");
            return;
        };
        self.merge_text(&contents);
    }

    /// Разбирает содержимое файла `hosts`.
    pub fn merge_text(&mut self, contents: &str) {
        for line in contents.lines() {
            let line = line.split('#').next().unwrap_or_default();
            let mut parts = line.split_whitespace();
            let Some(address) = parts.next().and_then(|a| a.parse::<IpAddr>().ok()) else {
                continue;
            };
            for name in parts {
                self.add(name, address);
            }
        }
    }
}

/// Где лежит системный файл `hosts`.
fn system_hosts_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let root = std::env::var_os("SystemRoot")?;
        Some(PathBuf::from(root).join(r"System32\drivers\etc\hosts"))
    }
    #[cfg(not(windows))]
    {
        Some(PathBuf::from("/etc/hosts"))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn looks_up_by_normalized_name() {
        let mut hosts = Hosts::new();
        hosts.add("Example.COM.", IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(
            hosts.lookup("example.com"),
            Some([IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))].as_slice())
        );
    }

    #[test]
    fn parses_a_hosts_file() {
        let mut hosts = Hosts::new();
        hosts.merge_text(
            "127.0.0.1 localhost\n\
             # комментарий\n\
             \n\
             0.0.0.0  ads.example  tracker.example   # реклама в никуда\n",
        );

        assert!(hosts.lookup("localhost").is_some());
        assert_eq!(hosts.lookup("ads.example"), hosts.lookup("tracker.example"));
        assert_eq!(hosts.len(), 3);
    }

    #[test]
    fn ignores_garbage_lines() {
        let mut hosts = Hosts::new();
        hosts.merge_text("не адрес вообще\n::1 localhost6\nтолько-текст\n");
        assert!(hosts.lookup("localhost6").is_some());
        assert_eq!(hosts.len(), 1);
    }

    #[test]
    fn trailing_comments_are_stripped() {
        let mut hosts = Hosts::new();
        hosts.merge_text("1.2.3.4 example.com # это комментарий\n");
        assert!(hosts.lookup("example.com").is_some());
        assert!(hosts.lookup("это").is_none());
    }

    #[test]
    fn one_name_can_have_several_addresses() {
        let mut hosts = Hosts::new();
        hosts.merge_text("1.2.3.4 example.com\n5.6.7.8 example.com\n");
        assert_eq!(hosts.lookup("example.com").map(<[IpAddr]>::len), Some(2));
    }

    #[test]
    fn missing_system_file_is_not_fatal() {
        let mut hosts = Hosts::new();
        hosts.add("mine.example", IpAddr::V4(Ipv4Addr::LOCALHOST));
        hosts.merge_system();
        assert!(hosts.lookup("mine.example").is_some());
    }

    #[test]
    fn empty_set_finds_nothing() {
        let hosts = Hosts::new();
        assert!(hosts.is_empty());
        assert!(hosts.lookup("example.com").is_none());
    }
}
