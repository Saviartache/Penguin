//! `ProcessIdentity`: pid, путь, имя, пользователь. Правило сравнивает именно это.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

pub use penguin_core::path::{file_name, normalize as normalize_path};

/// Кто владеет соединением. Поля в `Arc`: личность раздаётся многим соединениям.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    /// Идентификатор процесса (переиспользуется системой).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_comes_from_the_path_the_rules_compare() {
        let identity = ProcessIdentity::new(1, r"C:\Program Files\App\App.exe");
        assert_eq!(&*identity.name, file_name(&identity.path));
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
