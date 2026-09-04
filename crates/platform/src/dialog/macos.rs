//! macOS: `osascript` и `choose file`.
//!
//! Окно выбора у системы есть, но живёт оно в AppKit, а до AppKit из Rust без
//! привязок к Objective-C не дотянуться. `osascript` — тот же самый диалог,
//! показанный чужими руками.

use std::path::PathBuf;

use crate::command;
use crate::error::{PlatformError, PlatformResult};

/// Показывает окно и ждёт ответа.
pub(super) fn pick_program(title: &str, _filter: &str) -> PlatformResult<Option<PathBuf>> {
    // Вид файлов не отбирается: у программ в macOS расширения нет — оно есть
    // у каталога `.app`, внутрь которого и надо попасть.
    let line = script(title);
    match command::run("osascript", &["-e", line.as_str()]) {
        Ok(output) => Ok(chosen(&output)),
        // Отказ приходит ненулевым кодом возврата. Слова в сообщении
        // переведены, коды — нет, поэтому решает код.
        Err(failure) if failure.code().is_some() => Ok(None),
        Err(failure) => Err(failure.into_error(PlatformError::Dialog, "выбор файла")),
    }
}

/// Сценарий, который открывает окно и печатает путь.
///
/// `showing package contents` здесь обязателен. Программа в macOS — это
/// каталог `.app`, а правило сравнивает путь к двоичному файлу внутри него
/// (`.../Contents/MacOS/...`): без этого человек выбрал бы каталог, правило
/// собралось бы и не сработало ни разу.
fn script(title: &str) -> String {
    format!(
        "POSIX path of (choose file with prompt \"{}\" with showing package contents)",
        escape(title)
    )
}

/// Прячет от AppleScript то, чем у него заканчивается строка.
fn escape(value: &str) -> String {
    value.replace('\\', r"\\").replace('"', "\\\"")
}

/// Что сценарий напечатал.
///
/// Пустая строка — отказ: путь из пустоты стал бы правилом на корень файловой
/// системы.
fn chosen(output: &str) -> Option<PathBuf> {
    let path = output.trim();
    (!path.is_empty()).then(|| PathBuf::from(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_script_opens_packages() {
        // Без этого выбрали бы каталог `.app`, а правило сравнивает путь к
        // двоичному файлу внутри него.
        assert!(script("Выберите программу").contains("showing package contents"));
    }

    #[test]
    fn a_quote_in_the_title_does_not_end_the_string() {
        // Кавычка в подписи оборвала бы строку сценария, и `osascript`
        // отказался бы разбирать его целиком.
        let quoted = script(r#"Выберите "программу""#);
        assert!(quoted.contains(r#"\"программу\""#), "{quoted}");
    }

    #[test]
    fn the_answer_loses_its_newline() {
        assert_eq!(
            chosen("/usr/bin/curl\n"),
            Some(PathBuf::from("/usr/bin/curl"))
        );
        assert!(chosen("  \n").is_none());
    }
}
