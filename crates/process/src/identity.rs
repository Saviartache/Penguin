//! `ProcessIdentity`: pid, путь, имя, пользователь. Правило сравнивает именно это.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

// Приведение пути живёт в `core`: тот же путь приходит и от системы, и из
// файла настроек, и из окна выбора файла в интерфейсе, — а тот про процессы
// ничего не знает и знать не должен.
pub use penguin_core::path::{file_name, normalize as normalize_path};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_comes_from_the_path_the_rules_compare() {
        // Приведение пути живёт в `core`, но личность обязана собираться из
        // приведённого: имя, взятое из сырого пути, разошлось бы с ним
        // регистром.
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
