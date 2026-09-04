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
        Err(err) if refused(err.reason()) => {
            tracing::info!("человек отказался дать права");
            Ok(false)
        }
        // Всё остальное — настоящий сбой, и молчать о нём нельзя: снаружи он
        // выглядит так же, как отказ, а лечится совсем иначе.
        Err(err) => Err(err.into_error(PlatformError::Service, "повышение прав")),
    }
}

/// Отказался ли человек в окне.
///
/// Отказ система обозначает номером ошибки `-128`, и номер этот — не слово: он
/// один и тот же на любом языке. Разбирать сообщение целиком было бы нельзя,
/// а найти в нём номер — можно.
fn refused(reason: &str) -> bool {
    reason.contains("-128")
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
    fn a_cancelled_dialog_is_not_a_failure() {
        // Номер `-128` система ставит на отказ человека и не переводит его;
        // само сообщение приходит на языке системы, и опираться на него
        // нельзя.
        assert!(refused(
            "execution error: Пользователь отменил операцию. (-128)"
        ));
        assert!(refused("execution error: User canceled. (-128)"));
        assert!(!refused(
            "execution error: osascript is not allowed (-1743)"
        ));
        assert!(!refused("sh: penguin: command not found"));
    }

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
