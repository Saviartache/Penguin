//! Тема кита и её сохранение между запусками.
//!
//! Хранится в отдельном файле и читается до связи с демоном: окно открывается в
//! последней теме на этой машине, даже если демона нет.

use std::path::PathBuf;

use uikit::ThemeType;

/// Имя файла с темой.
const THEME_FILE: &str = "theme.json";

/// Читает сохранённую тему; любая неудача даёт умолчание, падать из-за темы нельзя.
pub fn load() -> ThemeType {
    let Some(path) = theme_path() else {
        return ThemeType::default();
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return ThemeType::default();
    };
    from_name(raw.trim().trim_matches('"'))
}

/// Сохраняет тему.
pub fn save(theme: ThemeType) {
    let Some(path) = theme_path() else { return };

    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return;
    }
    let _ = std::fs::write(path, to_name(theme));
}

/// Имя темы в файле: своё, не `Debug` — тот менялся бы вместе с вариантами кита.
pub fn to_name(theme: ThemeType) -> &'static str {
    match theme {
        ThemeType::LightBlue => "light-blue",
        ThemeType::LightGreen => "light-green",
        ThemeType::LightOrange => "light-orange",
        ThemeType::LightPurple => "light-purple",
        ThemeType::Dark => "dark",
    }
}

/// Тема по имени; незнакомое (файл новой версии) — умолчание.
pub fn from_name(name: &str) -> ThemeType {
    match name {
        "light-blue" => ThemeType::LightBlue,
        "light-green" => ThemeType::LightGreen,
        "light-orange" => ThemeType::LightOrange,
        "light-purple" => ThemeType::LightPurple,
        "dark" => ThemeType::Dark,
        _ => ThemeType::default(),
    }
}

fn theme_path() -> Option<PathBuf> {
    penguin_config::Paths::user()
        .ok()
        .map(|paths| paths.config_dir().join(THEME_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_theme_round_trips() {
        for theme in ThemeType::all().iter().copied() {
            assert_eq!(
                from_name(to_name(theme)),
                theme,
                "тема {theme:?} не восстановилась"
            );
        }
    }

    #[test]
    fn unknown_name_falls_back_to_default() {
        assert_eq!(from_name("радужная"), ThemeType::default());
        assert_eq!(from_name(""), ThemeType::default());
    }

    #[test]
    fn names_are_stable_and_readable() {
        assert_eq!(to_name(ThemeType::Dark), "dark");
        assert_eq!(to_name(ThemeType::LightBlue), "light-blue");
    }

    #[test]
    fn loading_never_panics() {
        let _ = load();
    }
}
