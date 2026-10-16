//! Путь к исполняемому файлу в виде, в котором его сравнивают правила.

/// Приводит путь к виду для сравнения: на Windows — нижний регистр и прямые слэши, иначе как есть.
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
        let from_api = normalize(r"C:\Program Files\App\App.exe");
        let from_config = normalize("c:/program files/app/app.exe");
        assert_eq!(from_api, from_config);
        assert_eq!(from_api, "c:/program files/app/app.exe");
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_paths_keep_their_case() {
        assert_ne!(normalize("/usr/bin/App"), normalize("/usr/bin/app"));
    }
}
