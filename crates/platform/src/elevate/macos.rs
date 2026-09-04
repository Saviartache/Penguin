//! macOS: запрос прав через окно системы.
//!
//! Своего `sudo` с окном в macOS нет, зато есть `do shell script … with
//! administrator privileges`: он показывает то самое окно с отпечатком или
//! паролем и выполняет команду от суперпользователя. Ничего лучше для
//! программы без окна терминала система не предлагает.

use crate::error::{PlatformError, PlatformResult};

/// Программа, исполняющая сценарии системы.
const OSASCRIPT: &str = "/usr/bin/osascript";

/// Запускает себя же с правами администратора и ждёт завершения.
pub(super) fn run_elevated(args: &[&str]) -> PlatformResult<bool> {
    let executable = std::env::current_exe()
        .map_err(|err| PlatformError::Service(format!("не удалось узнать свой путь: {err}")))?;

    let command = shell_command(&executable.display().to_string(), args);
    let script = format!("do shell script \"{command}\" with administrator privileges");

    match crate::command::run(OSASCRIPT, &["-e", &script]) {
        Ok(_) => Ok(true),
        // Отказ в окне и неудача самой команды выглядят одинаково — ненулевым
        // кодом возврата. Отличить их нечем, да и незачем: и то и другое
        // означает «не получилось».
        Err(err) => {
            tracing::debug!(?err, "права не получены");
            Ok(false)
        }
    }
}

/// Команда для оболочки, завёрнутая в строку сценария.
///
/// Экранирование двойное, и в этом вся трудность: сперва путь с пробелом
/// закрывается кавычками для оболочки, а потом эти кавычки закрываются для
/// самого сценария. Ошибка здесь означает команду, которая выполнится не так,
/// как задумана, — с правами суперпользователя.
fn shell_command(executable: &str, args: &[&str]) -> String {
    let mut parts = vec![quote(executable)];
    parts.extend(args.iter().map(|argument| quote(argument)));

    // Кавычки и обратные слэши, попавшие в готовую команду, закрываются ещё
    // раз — теперь для строки сценария.
    parts.join(" ").replace('\\', "\\\\").replace('"', "\\\"")
}

/// Заключает часть команды в одинарные кавычки для оболочки.
///
/// Одинарные, а не двойные: внутри них оболочка не подставляет ни переменных,
/// ни результатов команд, и путь вида `/дом/$(rm -rf ~)` остаётся путём.
fn quote(part: &str) -> String {
    // Внутри одинарных кавычек нельзя ничего экранировать, поэтому саму
    // кавычку приходится выносить наружу: `'` → `'\''`.
    format!("'{}'", part.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_with_spaces_stays_one_argument() {
        // Путь пользователя почти всегда содержит пробел.
        let command = shell_command(
            "/Applications/Мои программы/penguin",
            &["service", "install"],
        );
        assert!(
            command.contains("'/Applications/Мои программы/penguin'"),
            "{command}"
        );
    }

    #[test]
    fn a_substitution_in_the_path_stays_a_path() {
        // Команда выполняется от суперпользователя: подстановка, принятая за
        // команду, — это уже не ошибка, а дыра.
        let command = shell_command("/дом/$(touch /tmp/beda)/penguin", &[]);
        assert!(
            command.starts_with("'/дом/$(touch /tmp/beda)/penguin'"),
            "{command}"
        );
    }

    #[test]
    fn a_quote_in_the_path_does_not_end_the_argument() {
        // Кавычку приходится выносить наружу (`'` → `'\''`), а обратный слэш
        // из этой замены удваивается ещё раз — уже для строки сценария.
        // Оболочка увидит `'\''` после того, как сценарий снимет свой слой.
        let command = shell_command("/дом/it's mine/penguin", &[]);
        assert!(command.contains(r"it'\\''s mine"), "{command}");
    }

    #[test]
    fn a_double_quote_does_not_end_the_script_string() {
        // Незакрытая кавычка обрывает строку сценария, и остаток команды
        // становится его кодом — с правами суперпользователя.
        let command = shell_command("/дом/\"кавычки\"/penguin", &[]);
        for (index, _) in command.match_indices('"') {
            assert!(
                index > 0 && command.as_bytes()[index - 1] == b'\\',
                "кавычка без экранирования: {command}"
            );
        }
    }
}
