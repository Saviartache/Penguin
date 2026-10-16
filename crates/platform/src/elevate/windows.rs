//! Windows: перезапуск через `ShellExecuteExW` с глаголом `runas` (окно UAC).

use crate::error::{PlatformError, PlatformResult};

/// Сколько ждать поднятый процесс: секунды на установку, с запасом на человека у окна UAC.
const WAIT_TIMEOUT_MS: u32 = 30_000;

/// Запускает себя же с правами администратора и ждёт завершения.
pub(super) fn run_elevated(args: &[&str]) -> PlatformResult<bool> {
    use std::os::windows::ffi::OsStrExt;

    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
    use windows::core::PCWSTR;

    fn wide(value: &str) -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let executable = std::env::current_exe()
        .map_err(|err| PlatformError::Service(format!("не удалось узнать свой путь: {err}")))?;

    let verb = wide("runas");
    let file = wide(&executable.to_string_lossy());
    let parameters = wide(&command_line(args));

    let mut info = SHELLEXECUTEINFOW {
        cbSize: u32::try_from(std::mem::size_of::<SHELLEXECUTEINFOW>()).unwrap_or(0),
        // Без признака описатель процесса не вернётся и ждать нечего.
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    #[allow(unsafe_code, reason = "запуск процесса с повышением прав")]
    // SAFETY: строки в `info` живут до конца вызова.
    let started = unsafe { ShellExecuteExW(&mut info) }.is_ok();

    // Чаще всего это «Нет» в окне UAC; от ошибки не отличить, и не нужно.
    if !started {
        return Ok(false);
    }

    let process = HANDLE(info.hProcess.0);
    #[allow(unsafe_code, reason = "ожидание запущенного процесса")]
    // SAFETY: `process` возвращён `ShellExecuteExW` и открыт.
    let finished =
        unsafe { windows::Win32::System::Threading::WaitForSingleObject(process, WAIT_TIMEOUT_MS) };
    #[allow(unsafe_code, reason = "закрытие описателя процесса")]
    // SAFETY: закрывается ровно раз.
    unsafe {
        let _ = CloseHandle(process);
    }

    Ok(finished == WAIT_OBJECT_0)
}

/// Собирает аргументы в одну строку: Windows передаёт их так, и аргумент с пробелом нужен в кавычках.
fn command_line(args: &[&str]) -> String {
    args.iter()
        .map(|argument| {
            if argument.contains(' ') && !argument.starts_with('"') {
                format!("\"{argument}\"")
            } else {
                (*argument).to_owned()
            }
        })
        .collect::<Vec<String>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_with_spaces_stays_one_argument() {
        let line = command_line(&[
            "service",
            "ensure",
            "--config-dir",
            "C:/Program Files/Penguin",
        ]);
        assert!(line.ends_with("\"C:/Program Files/Penguin\""), "{line}");
    }

    #[test]
    fn a_plain_argument_gets_no_quotes() {
        assert_eq!(command_line(&["service", "install"]), "service install");
    }
}
