//! Выбор темы кита и её сохранение между запусками.
//!
//! Тема хранится в отдельном маленьком файле, а не в общих настройках, и
//! читается **до** того, как окно свяжется с демоном. Причина простая: демон
//! может быть не запущен, а окно всё равно должно открыться в той теме, в
//! которой его закрыли, — иначе каждый запуск начинается со вспышки чужого
//! цвета.
//!
//! В общих настройках тема тоже есть: тот же профиль на другой машине должен
//! выглядеть так же. Расхождение разрешается в пользу локального файла — он
//! отражает последний выбор именно на этой машине.

use std::path::PathBuf;

use uikit::ThemeType;

/// Имя файла с темой.
const THEME_FILE: &str = "theme.json";

/// Читает сохранённую тему.
///
/// Любая неудача — отсутствие файла, испорченное содержимое, нет прав —
/// молча даёт умолчание: падать при запуске из-за темы недопустимо.
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

/// Имя темы в файле.
///
/// Своё, а не производное от `Debug`: производное менялось бы вместе с
/// именами вариантов в ките, и файл, записанный старой версией, перестал бы
/// читаться.
pub fn to_name(theme: ThemeType) -> &'static str {
    match theme {
        ThemeType::LightBlue => "light-blue",
        ThemeType::LightGreen => "light-green",
        ThemeType::LightOrange => "light-orange",
        ThemeType::LightPurple => "light-purple",
        ThemeType::Dark => "dark",
    }
}

/// Тема по имени.
pub fn from_name(name: &str) -> ThemeType {
    match name {
        "light-blue" => ThemeType::LightBlue,
        "light-green" => ThemeType::LightGreen,
        "light-orange" => ThemeType::LightOrange,
        "light-purple" => ThemeType::LightPurple,
        "dark" => ThemeType::Dark,
        // Незнакомое имя — файл от более новой версии. Умолчание лучше, чем
        // отказ запускаться.
        _ => ThemeType::default(),
    }
}

/// Где лежит файл темы.
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
        // Имя в файле — контракт с самим собой между запусками.
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
        // Файл от более новой версии не повод отказаться запускаться.
        assert_eq!(from_name("радужная"), ThemeType::default());
        assert_eq!(from_name(""), ThemeType::default());
    }

    #[test]
    fn names_are_stable_and_readable() {
        // Производное от `Debug` менялось бы вместе с именами вариантов в
        // ките, и старый файл перестал бы читаться.
        assert_eq!(to_name(ThemeType::Dark), "dark");
        assert_eq!(to_name(ThemeType::LightBlue), "light-blue");
    }

    #[test]
    fn loading_never_panics() {
        // Читается при запуске, до всего остального.
        let _ = load();
    }
}
