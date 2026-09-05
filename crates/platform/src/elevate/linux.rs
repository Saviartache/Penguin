//! Linux: запрос прав через `pkexec`.
//!
//! `sudo` здесь не годится: он спрашивает пароль в терминале, которого у окна
//! нет. `pkexec` обращается к службе polkit, а та показывает окно того
//! рабочего стола, за которым сидит человек, — то же самое, что делают
//! системные настройки, когда просят права.
//!
//! Аргументы передаются как есть, без кавычек: `pkexec` запускает программу
//! напрямую, и кавычка в пути стала бы частью имени каталога.

use crate::command;
use crate::error::{PlatformError, PlatformResult};

/// Программа, запрашивающая права у polkit.
const PKEXEC: &str = "pkexec";

/// Запускает себя же с правами администратора и ждёт завершения.
pub(super) fn run_elevated(args: &[&str]) -> PlatformResult<bool> {
    let executable = std::env::current_exe()
        .map_err(|err| PlatformError::Service(format!("не удалось узнать свой путь: {err}")))?;

    let executable = executable.display().to_string();
    let mut arguments = vec![executable.as_str()];
    arguments.extend_from_slice(args);

    match command::run(PKEXEC, &arguments) {
        Ok(_) => Ok(true),
        Err(err) if err.is_not_found() => Err(PlatformError::PermissionDenied(format!(
            "не найдена программа `{PKEXEC}`: установите polkit \
             или запустите команду через `sudo penguin {}`",
            args.join(" ")
        ))),
        Err(err) if matches!(err.code(), Some(DISMISSED | NOT_AUTHORISED)) => {
            tracing::info!("человек отказался дать права");
            Ok(false)
        }
        // Всё остальное — настоящий сбой, и молчать о нём нельзя: снаружи он
        // выглядит так же, как отказ, а лечится совсем иначе.
        Err(err) => Err(err.into_error(PlatformError::Service, "повышение прав")),
    }
}

/// Окно закрыли, не ответив.
///
/// Коды заданы самим `pkexec` и, в отличие от сообщений, не переводятся.
const DISMISSED: i32 = 126;

/// Проверка не пройдена — не тот пароль или нет права становиться
/// администратором.
const NOT_AUTHORISED: i32 = 127;
