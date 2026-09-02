//! Список запущенных приложений для выбора в GUI.

use penguin_ipc::schema::{AppInfo, Response};

/// Отдаёт список запущенных приложений.
///
/// Свёрнутый по пути: браузер — это два десятка процессов с одним и тем же
/// исполняемым файлом, а правило пишется на путь, а не на номер процесса.
pub fn list() -> Response {
    let apps = penguin_process::system_enumerator()
        .list_apps()
        .into_iter()
        .map(|app| AppInfo {
            path: app.identity.path.to_string(),
            name: app.identity.name.to_string(),
            instances: app.instances,
        })
        .collect();

    Response::Processes { apps }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_never_panics() {
        let Response::Processes { apps } = list() else {
            panic!("не тот ответ")
        };
        let _ = apps.len();
    }

    #[cfg(windows)]
    #[test]
    fn finds_something_on_a_running_system() {
        let Response::Processes { apps } = list() else {
            panic!("не тот ответ")
        };
        assert!(!apps.is_empty(), "не найдено ни одного приложения");
    }

    #[cfg(windows)]
    #[test]
    fn paths_are_unique() {
        // Свёртка по пути обязана убрать повторы: иначе список для выбора
        // состоял бы из двадцати строк с одним и тем же браузером.
        let Response::Processes { apps } = list() else {
            panic!("не тот ответ")
        };

        let mut paths: Vec<&str> = apps.iter().map(|app| app.path.as_str()).collect();
        let before = paths.len();
        paths.sort_unstable();
        paths.dedup();
        assert_eq!(paths.len(), before, "в списке остались повторы");
    }
}
