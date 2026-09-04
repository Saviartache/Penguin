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
    if !command::exists(PKEXEC) {
        return Err(PlatformError::PermissionDenied(format!(
            "не найдена программа `{PKEXEC}`: установите polkit \
             или запустите команду через `sudo penguin {}`",
            args.join(" ")
        )));
    }

    let executable = std::env::current_exe()
        .map_err(|err| PlatformError::Service(format!("не удалось узнать свой путь: {err}")))?;

    let executable = executable.display().to_string();
    let mut arguments = vec![executable.as_str()];
    arguments.extend_from_slice(args);

    match command::run(PKEXEC, &arguments) {
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
