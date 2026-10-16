//! macOS: права через `do shell script … with administrator privileges` (системное окно).

use crate::error::{PlatformError, PlatformResult};

/// Программа, исполняющая сценарии системы.
const OSASCRIPT: &str = "/usr/bin/osascript";

/// Текст окна: согласие вслепую равно отсутствию согласия.
const PROMPT: &str = "Penguin ставит и запускает службу тоннеля";

/// Запускает себя же с правами администратора и ждёт завершения.
pub(super) fn run_elevated(args: &[&str]) -> PlatformResult<bool> {
    let executable = std::env::current_exe()
        .map_err(|err| PlatformError::Service(format!("не удалось узнать свой путь: {err}")))?;

    let command = shell_command(&executable.display().to_string(), args);
    // `with prompt`: иначе окно безымянное. Строка наша, экранировать нечего.
    let script = format!(
        "do shell script \"{command}\" with prompt \"{PROMPT}\" with administrator privileges"
    );

    match crate::command::run(OSASCRIPT, &["-e", &script]) {
        Ok(_) => Ok(true),
        Err(err) if refused(err.reason()) => {
            tracing::info!("человек отказался дать права");
            Ok(false)
        }
        // Настоящий сбой не должен выглядеть как отказ.
        Err(err) => Err(err.into_error(PlatformError::Service, "повышение прав")),
    }
}

/// Отказ человека система помечает номером `-128` (на любом языке одинаковым).
fn refused(reason: &str) -> bool {
    reason.contains("-128")
}

/// Команда для оболочки в строке сценария: двойное экранирование (кавычки оболочки, затем
/// сценария); ошибка здесь — не та команда с правами суперпользователя.
fn shell_command(executable: &str, args: &[&str]) -> String {
    let mut parts = vec![quote(executable)];
    parts.extend(args.iter().map(|argument| quote(argument)));

    parts.join(" ").replace('\\', "\\\\").replace('"', "\\\"")
}

/// Одинарные кавычки оболочки: внутри них нет подстановок; сама кавычка выносится (`'` → `'\''`).
fn quote(part: &str) -> String {
    format!("'{}'", part.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cancelled_dialog_is_not_a_failure() {
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
    fn the_prompt_cannot_break_the_script() {
        assert!(!PROMPT.contains(['"', '\\']), "{PROMPT}");
        assert!(!PROMPT.is_empty());
    }

    #[test]
    fn a_path_with_spaces_stays_one_argument() {
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
        let command = shell_command("/дом/$(touch /tmp/beda)/penguin", &[]);
        assert!(
            command.starts_with("'/дом/$(touch /tmp/beda)/penguin'"),
            "{command}"
        );
    }

    #[test]
    fn a_quote_in_the_path_does_not_end_the_argument() {
        // `'\''` после снятия слоя сценария: обратный слэш удваивается.
        let command = shell_command("/дом/it's mine/penguin", &[]);
        assert!(command.contains(r"it'\\''s mine"), "{command}");
    }

    #[test]
    fn a_double_quote_does_not_end_the_script_string() {
        let command = shell_command("/дом/\"кавычки\"/penguin", &[]);
        for (index, _) in command.match_indices('"') {
            assert!(
                index > 0 && command.as_bytes()[index - 1] == b'\\',
                "кавычка без экранирования: {command}"
            );
        }
    }
}
