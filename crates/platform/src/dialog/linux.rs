//! Linux: `zenity` (GNOME) или `kdialog` (KDE), что нашлось.

use std::path::PathBuf;

use crate::command;
use crate::error::{PlatformError, PlatformResult};

/// Показывает окно и ждёт ответа; вид файлов не отбирается (у программ в Linux нет расширения).
pub(super) fn pick_program(title: &str, _filter: &str) -> PlatformResult<Option<PathBuf>> {
    if command::exists("zenity") {
        let titled = format!("--title={title}");
        return ask("zenity", &["--file-selection", titled.as_str()]);
    }
    if command::exists("kdialog") {
        return ask("kdialog", &["--title", title, "--getopenfilename", "."]);
    }

    Err(PlatformError::Dialog(
        "окно выбора файла показывать нечем: нет ни `zenity`, ни `kdialog`".to_owned(),
    ))
}

/// Спрашивает у программы рабочего стола; ненулевой код — отказ (слова переведены, коды нет).
fn ask(program: &str, arguments: &[&str]) -> PlatformResult<Option<PathBuf>> {
    match command::run(program, arguments) {
        Ok(output) => Ok(chosen(&output)),
        Err(failure) if failure.code().is_some() => Ok(None),
        Err(failure) => Err(failure.into_error(PlatformError::Dialog, "выбор файла")),
    }
}

/// Выбранный путь; пустая строка — отказ (`kdialog` так отвечает на закрытое окно).
fn chosen(output: &str) -> Option<PathBuf> {
    let path = output.trim();
    (!path.is_empty()).then(|| PathBuf::from(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_answer_loses_its_newline() {
        assert_eq!(
            chosen("/usr/bin/curl\n"),
            Some(PathBuf::from("/usr/bin/curl"))
        );
    }

    #[test]
    fn an_empty_answer_is_a_refusal() {
        assert!(chosen("").is_none());
        assert!(chosen("  \n").is_none());
    }

    #[test]
    fn a_missing_desktop_program_is_named() {
        if command::exists("zenity") || command::exists("kdialog") {
            return;
        }
        let err = pick_program("Выберите программу", "Программы").expect_err("нечем показать");
        assert!(err.to_string().contains("zenity"), "{err}");
    }
}
