//! Список запущенных процессов — для выбора приложения в GUI.
//!
//! Нужен ровно одному экрану: пользователь отмечает мышью приложения, которые
//! должны идти мимо тоннеля, и видеть он хочет то, что запущено прямо сейчас.
//! На горячем пути этот список не участвует.

use std::collections::HashMap;

use crate::identity::ProcessIdentity;

/// Запущенное приложение в списке для выбора.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningApp {
    /// Личность процесса.
    pub identity: ProcessIdentity,
    /// Сколько процессов с этим же путём запущено.
    ///
    /// Браузер — это два десятка процессов с одним путём. Показывать их
    /// по отдельности бессмысленно: правило пишется на путь, а не на номер.
    pub instances: usize,
}

/// Список запущенных приложений.
pub trait ProcessEnumerator: Send + Sync + 'static {
    /// Все процессы, до которых удалось дотянуться.
    fn list(&self) -> Vec<ProcessIdentity>;

    /// То же, свёрнутое по пути и отсортированное по имени.
    ///
    /// Реализация по умолчанию годится всем: сворачивание не зависит от
    /// платформы.
    fn list_apps(&self) -> Vec<RunningApp> {
        let mut by_path: HashMap<String, RunningApp> = HashMap::new();

        for identity in self.list() {
            by_path
                .entry(identity.path.to_string())
                .and_modify(|app| app.instances += 1)
                .or_insert(RunningApp {
                    identity,
                    instances: 1,
                });
        }

        let mut apps: Vec<RunningApp> = by_path.into_values().collect();
        apps.sort_by(|a, b| {
            a.identity
                .name
                .to_lowercase()
                .cmp(&b.identity.name.to_lowercase())
        });
        apps
    }
}

/// Перечислитель для текущей платформы.
pub fn system_enumerator() -> Box<dyn ProcessEnumerator> {
    #[cfg(windows)]
    {
        Box::new(crate::platform::windows::icon::WindowsEnumerator)
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(crate::platform::linux::LinuxEnumerator)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(crate::platform::macos::MacosEnumerator)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Box::new(EmptyEnumerator)
    }
}

/// Перечислитель, не находящий ничего.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmptyEnumerator;

impl ProcessEnumerator for EmptyEnumerator {
    fn list(&self) -> Vec<ProcessIdentity> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake(Vec<ProcessIdentity>);

    impl ProcessEnumerator for Fake {
        fn list(&self) -> Vec<ProcessIdentity> {
            self.0.clone()
        }
    }

    #[test]
    fn collapses_instances_of_the_same_app() {
        // Браузер — это два десятка процессов с одним путём; в списке для
        // выбора он должен быть одной строкой.
        let enumerator = Fake(vec![
            ProcessIdentity::new(1, "/apps/chrome"),
            ProcessIdentity::new(2, "/apps/chrome"),
            ProcessIdentity::new(3, "/apps/chrome"),
            ProcessIdentity::new(4, "/apps/editor"),
        ]);

        let apps = enumerator.list_apps();
        assert_eq!(apps.len(), 2);

        let chrome = apps
            .iter()
            .find(|a| &*a.identity.name == "chrome")
            .expect("есть");
        assert_eq!(chrome.instances, 3);
    }

    #[test]
    fn sorts_by_name() {
        let enumerator = Fake(vec![
            ProcessIdentity::new(1, "/apps/zed"),
            ProcessIdentity::new(2, "/apps/Alpha"),
            ProcessIdentity::new(3, "/apps/mid"),
        ]);
        let names: Vec<String> = enumerator
            .list_apps()
            .iter()
            .map(|a| a.identity.name.to_lowercase())
            .collect();
        assert_eq!(names, vec!["alpha", "mid", "zed"]);
    }

    #[test]
    fn empty_enumerator_yields_nothing() {
        assert!(EmptyEnumerator.list_apps().is_empty());
    }
}
