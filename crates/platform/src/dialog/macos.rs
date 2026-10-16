//! macOS: `osascript` и `choose file` (до AppKit из Rust без привязок не дотянуться).

use std::path::PathBuf;

use crate::command;
use crate::error::{PlatformError, PlatformResult};

/// Показывает окно и ждёт ответа; вид файлов не отбирается (программа — каталог `.app`).
pub(super) fn pick_program(title: &str, _filter: &str) -> PlatformResult<Option<PathBuf>> {
    let line = script(title);
    match command::run("osascript", &["-e", line.as_str()]) {
        Ok(output) => Ok(chosen(&output)),
        // Отказ — ненулевой код (слова переведены, коды нет).
        Err(failure) if failure.code().is_some() => Ok(None),
        Err(failure) => Err(failure.into_error(PlatformError::Dialog, "выбор файла")),
    }
}

/// Сценарий окна; `showing package contents` нужен, чтобы выбрать двоичный файл внутри `.app`,
/// с путём к которому сравнивается правило.
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

/// Выбранный путь; пустая строка — отказ.
fn chosen(output: &str) -> Option<PathBuf> {
    let path = output.trim();
    (!path.is_empty()).then(|| PathBuf::from(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_script_opens_packages() {
        assert!(script("Выберите программу").contains("showing package contents"));
    }

    #[test]
    fn a_quote_in_the_title_does_not_end_the_string() {
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
