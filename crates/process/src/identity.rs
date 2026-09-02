//! `ProcessIdentity`: pid, путь, имя, пользователь. Правило сравнивает именно это.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// Кто владеет соединением.
///
/// Поля в `Arc`, потому что личность одного процесса раздаётся сотням
/// соединений: браузер открывает их десятками в секунду, и копировать путь на
/// каждое — заметная работа впустую.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    /// Идентификатор процесса.
    ///
    /// Система переиспользует номера, поэтому сам по себе он ключом кэша не
    /// годится — только вместе с моментом запуска или с проверкой пути.
    pub pid: u32,
    /// Полный путь к исполняемому файлу в каноническом виде.
    pub path: Arc<str>,
    /// Имя файла без пути.
    pub name: Arc<str>,
    /// Владелец процесса, если удалось определить.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<Arc<str>>,
}

impl ProcessIdentity {
    /// Собирает личность, приводя путь к каноническому виду.
    pub fn new(pid: u32, path: impl AsRef<str>) -> Self {
        let path = normalize_path(path.as_ref());
        let name = file_name(&path).to_owned();
        Self {
            pid,
            path: Arc::from(path),
            name: Arc::from(name),
            user: None,
        }
    }

    /// Добавляет владельца.
    pub fn with_user(mut self, user: impl AsRef<str>) -> Self {
        self.user = Some(Arc::from(user.as_ref()));
        self
    }
}

/// Приводит путь к виду, в котором его сравнивают правила.
///
/// На Windows — нижний регистр и прямые слэши. Без этого один и тот же файл
/// не совпадает сам с собой: система выдаёт `C:\Program Files\...` из одного
/// вызова и `c:/program files/...` из другого, а правило пользователь
/// записывает третьим способом.
///
/// На остальных системах путь чувствителен к регистру и не трогается: два
/// файла с именами, различающимися регистром, — это два разных файла.
pub fn normalize_path(path: &str) -> String {
    #[cfg(windows)]
    {
        path.trim().replace('\\', "/").to_lowercase()
    }
    #[cfg(not(windows))]
    {
        path.trim().to_owned()
    }
}

/// Имя файла из нормализованного пути.
pub fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_file_name() {
        assert_eq!(file_name("c:/program files/app/app.exe"), "app.exe");
        assert_eq!(file_name("/usr/bin/curl"), "curl");
        assert_eq!(file_name("app.exe"), "app.exe");
    }

    #[cfg(windows)]
    #[test]
    fn windows_paths_are_case_and_separator_insensitive() {
        // Система выдаёт путь то так, то эдак, а пользователь пишет третьим
        // способом. Все три обязаны совпасть.
        let from_api = normalize_path(r"C:\Program Files\App\App.exe");
        let from_config = normalize_path("c:/program files/app/app.exe");
        assert_eq!(from_api, from_config);
        assert_eq!(from_api, "c:/program files/app/app.exe");
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_paths_keep_their_case() {
        // Два файла, различающихся регистром, — это два разных файла.
        assert_ne!(
            normalize_path("/usr/bin/App"),
            normalize_path("/usr/bin/app")
        );
    }

    #[test]
    fn identity_derives_the_name_from_the_path() {
        let identity = ProcessIdentity::new(42, "/usr/bin/curl");
        assert_eq!(identity.pid, 42);
        assert_eq!(&*identity.name, "curl");
        assert!(identity.user.is_none());
    }

    #[test]
    fn identity_carries_the_user() {
        let identity = ProcessIdentity::new(1, "/usr/bin/curl").with_user("root");
        assert_eq!(identity.user.as_deref(), Some("root"));
    }
}
