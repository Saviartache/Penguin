//! Путь к исполняемому файлу в том виде, в каком его сравнивают правила.
//!
//! Здесь, а не у того, кто спрашивает систему о процессах: путь один и тот же
//! приходит с трёх сторон — от системы, из файла настроек и из окна выбора
//! файла, — и совпасть они обязаны все три. Копия приведения на каждой стороне
//! однажды разойдётся, и разойдётся молча: правило соберётся, а не сработает.

/// Приводит путь к виду, в котором его сравнивают правила.
///
/// На Windows — нижний регистр и прямые слэши. Без этого один и тот же файл
/// не совпадает сам с собой: система выдаёт `C:\Program Files\...` из одного
/// вызова и `c:/program files/...` из другого, а правило пользователь
/// записывает третьим способом.
///
/// На остальных системах путь чувствителен к регистру и не трогается: два
/// файла с именами, различающимися регистром, — это два разных файла.
pub fn normalize(path: &str) -> String {
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
        // Система выдаёт путь то так, то эдак, пользователь пишет третьим
        // способом, а окно выбора файла — четвёртым. Все обязаны совпасть.
        let from_api = normalize(r"C:\Program Files\App\App.exe");
        let from_config = normalize("c:/program files/app/app.exe");
        assert_eq!(from_api, from_config);
        assert_eq!(from_api, "c:/program files/app/app.exe");
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_paths_keep_their_case() {
        // Два файла, различающихся регистром, — это два разных файла.
        assert_ne!(normalize("/usr/bin/App"), normalize("/usr/bin/app"));
    }
}
