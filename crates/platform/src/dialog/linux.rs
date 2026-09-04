//! Linux: `zenity` или `kdialog`.
//!
//! Окна выбора файла у системы нет — оно есть у рабочего стола, и рабочих
//! столов два. `zenity` стоит там, где GNOME, `kdialog` — там, где KDE;
//! спрашиваем то, что нашлось.
//!
//! Своё окно вместо них рисовать нечем: у клиента нет ни GTK, ни Qt, и тащить
//! любой из них ради одного окна значит утроить размер программы.

use std::path::PathBuf;

use crate::command;
use crate::error::{PlatformError, PlatformResult};

/// Показывает окно и ждёт ответа.
pub(super) fn pick_program(title: &str, _filter: &str) -> PlatformResult<Option<PathBuf>> {
    // Вид файлов не отбирается: у программ в Linux расширения нет, и любой
    // отбор спрятал бы ровно то, что ищут.
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

/// Спрашивает у программы рабочего стола.
fn ask(program: &str, arguments: &[&str]) -> PlatformResult<Option<PathBuf>> {
    match command::run(program, arguments) {
        Ok(output) => Ok(chosen(&output)),
        // Программа запустилась и вышла с ненулевым кодом — так обе они
        // сообщают об отказе. Разбирать её слова нельзя: они переведены.
        Err(failure) if failure.code().is_some() => Ok(None),
        Err(failure) => Err(failure.into_error(PlatformError::Dialog, "выбор файла")),
    }
}

/// Что программа напечатала.
///
/// Пустая строка при нулевом коде — тоже отказ: так `kdialog` отвечает на окно,
/// закрытое крестиком, и путь из пустоты был бы правилом на каталог `/`.
fn chosen(output: &str) -> Option<PathBuf> {
    let path = output.trim();
    (!path.is_empty()).then(|| PathBuf::from(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_answer_loses_its_newline() {
        // Программа печатает путь строкой, и перевод строки достался бы имени
        // файла.
        assert_eq!(
            chosen("/usr/bin/curl\n"),
            Some(PathBuf::from("/usr/bin/curl"))
        );
    }

    #[test]
    fn an_empty_answer_is_a_refusal() {
        // Путь из пустоты стал бы правилом на корень файловой системы.
        assert!(chosen("").is_none());
        assert!(chosen("  \n").is_none());
    }

    #[test]
    fn a_missing_desktop_program_is_named() {
        // «Ничего не произошло» читается как поломка клиента; человек должен
        // узнать, чего именно не хватает.
        if command::exists("zenity") || command::exists("kdialog") {
            return;
        }
        let err = pick_program("Выберите программу", "Программы").expect_err("нечем показать");
        assert!(err.to_string().contains("zenity"), "{err}");
    }
}
