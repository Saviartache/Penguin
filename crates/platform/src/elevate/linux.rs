//! Linux: права через `pkexec` (polkit показывает окно рабочего стола; `sudo` ждёт терминал).

use crate::command;
use crate::error::{PlatformError, PlatformResult};

/// Программа, запрашивающая права у polkit.
const PKEXEC: &str = "pkexec";

/// Окно закрыли, не ответив (код `pkexec`, не переводится).
const DISMISSED: i32 = 126;

/// Проверка не пройдена: не тот пароль или нет права становиться администратором.
const NOT_AUTHORISED: i32 = 127;

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
        // Настоящий сбой не должен выглядеть как отказ.
        Err(err) => Err(err.into_error(PlatformError::Service, "повышение прав")),
    }
}
