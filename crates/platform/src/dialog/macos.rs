//! macOS: `osascript`, `choose file` и `choose file name` (до AppKit из Rust без привязок не
//! дотянуться).

use std::path::{Path, PathBuf};

use super::Kind;
use crate::command;
use crate::error::{PlatformError, PlatformResult};

/// Виды файлов программы: пакет `.app` и голый исполняемый файл.
const PROGRAM_TYPES: &str = r#"{"com.apple.application", "public.unix-executable"}"#;

/// Показывает окно и ждёт ответа. Пакет `.app` выбирается целиком, как в Finder:
/// с открытыми пакетами окно входит в него, как в папку.
pub(super) fn pick(kind: Kind, title: &str) -> PlatformResult<Option<PathBuf>> {
    match ask(&script(kind, title))? {
        Some(path) if kind == Kind::Program => executable(path).map(Some),
        other => Ok(other),
    }
}

/// Спрашивает, куда сохранить; о замене существующего файла окно спросит само.
pub(super) fn save(title: &str, name: &str) -> PlatformResult<Option<PathBuf>> {
    ask(&save_script(title, name))
}

fn ask(line: &str) -> PlatformResult<Option<PathBuf>> {
    match command::run("osascript", &["-e", line]) {
        Ok(output) => Ok(chosen(&output)),
        // Отказ — ненулевой код (слова переведены, коды нет).
        Err(failure) if failure.code().is_some() => Ok(None),
        Err(failure) => Err(failure.into_error(PlatformError::Dialog, "выбор файла")),
    }
}

fn script(kind: Kind, title: &str) -> String {
    let types = match kind {
        Kind::Program => format!(" of type {PROGRAM_TYPES}"),
        Kind::RuleList => String::new(),
    };
    format!(
        "POSIX path of (choose file with prompt \"{}\"{types})",
        escape(title)
    )
}

fn save_script(title: &str, name: &str) -> String {
    format!(
        "POSIX path of (choose file name with prompt \"{}\" default name \"{}\")",
        escape(title),
        escape(name)
    )
}

/// Прячет от AppleScript то, чем у него заканчивается строка.
fn escape(value: &str) -> String {
    value.replace('\\', r"\\").replace('"', "\\\"")
}

/// Выбранный путь без хвостовой черты (у пакета она есть); пустая строка — отказ.
fn chosen(output: &str) -> Option<PathBuf> {
    let path = output.trim();
    let path = path.strip_suffix('/').unwrap_or(path);
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// Исполняемый файл программы: правило сравнивает путь процесса, а это не пакет.
fn executable(path: PathBuf) -> PlatformResult<PathBuf> {
    if path.extension().is_none_or(|extension| extension != "app") {
        return Ok(path);
    }

    let plist = path.join("Contents/Info.plist");
    let plist = plist.to_string_lossy();
    let name = command::run(
        "plutil",
        &["-extract", "CFBundleExecutable", "raw", "-o", "-", &plist],
    )
    .map_err(|failure| failure.into_error(PlatformError::Dialog, "имя программы в пакете"))?;

    Ok(in_bundle(&path, name.trim()))
}

fn in_bundle(bundle: &Path, name: &str) -> PathBuf {
    bundle.join("Contents/MacOS").join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packages_are_chosen_whole() {
        let line = script(Kind::Program, "Выберите программу");
        assert!(!line.contains("package contents"), "{line}");
        assert!(line.contains("com.apple.application"), "{line}");
    }

    #[test]
    fn a_rule_list_is_any_file() {
        assert!(!script(Kind::RuleList, "Список").contains("of type"));
    }

    #[test]
    fn saving_offers_a_name() {
        let line = save_script("Куда", "rules.conf");
        assert!(line.contains(r#"choose file name with prompt "Куда" default name "rules.conf""#));
    }

    #[test]
    fn a_quote_in_the_title_does_not_end_the_string() {
        let quoted = script(Kind::Program, r#"Выберите "программу""#);
        assert!(quoted.contains(r#"\"программу\""#), "{quoted}");
    }

    #[test]
    fn the_answer_loses_its_newline_and_slash() {
        assert_eq!(
            chosen("/usr/bin/curl\n"),
            Some(PathBuf::from("/usr/bin/curl"))
        );
        assert_eq!(
            chosen("/Applications/Safari.app/\n"),
            Some(PathBuf::from("/Applications/Safari.app"))
        );
        assert!(chosen("  \n").is_none());
    }

    #[test]
    fn a_bare_executable_is_kept() {
        let path = PathBuf::from("/usr/bin/curl");
        assert_eq!(executable(path.clone()).expect("не пакет"), path);
    }

    #[test]
    fn a_package_gives_its_executable() {
        assert_eq!(
            in_bundle(Path::new("/Applications/Safari.app"), "Safari"),
            PathBuf::from("/Applications/Safari.app/Contents/MacOS/Safari")
        );
    }

    #[test]
    fn a_real_package_is_resolved() {
        let finder = PathBuf::from("/System/Library/CoreServices/Finder.app");
        if !finder.exists() {
            return;
        }
        assert_eq!(
            executable(finder.clone()).expect("plutil читает Info.plist"),
            finder.join("Contents/MacOS/Finder")
        );
    }
}
