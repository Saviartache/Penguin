//! Windows: перезапуск себя через `ShellExecuteW` с глаголом `runas`.
//!
//! Права здесь не выдаются процессу на ходу: их получает только новый
//! процесс, запущенный с этим глаголом, — то самое окно UAC.

use crate::error::{PlatformError, PlatformResult};

/// Сколько ждать поднятый процесс.
///
/// Установка службы вместе с окном UAC укладывается в секунды; полминуты —
/// с запасом на медленную машину и на человека, который отвлёкся. Дольше ждать
/// незачем: окно всё это время не отвечает.
const WAIT_TIMEOUT_MS: u32 = 30_000;

/// Запускает себя же с правами администратора и ждёт завершения.
pub(super) fn run_elevated(args: &[&str]) -> PlatformResult<bool> {
    use std::os::windows::ffi::OsStrExt;

    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
    use windows::core::PCWSTR;

    /// Строка в том виде, в каком её принимает Windows.
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
        // Размер структуры — способ, которым Windows узнаёт её версию.
        cbSize: u32::try_from(std::mem::size_of::<SHELLEXECUTEINFOW>()).unwrap_or(0),
        // Без этого признака описатель процесса не возвращается, и дождаться
        // его завершения нечем.
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        // Окна у поднятого процесса нет: он делает своё дело и молча выходит.
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    #[allow(unsafe_code, reason = "запуск процесса с повышением прав")]
    let started = unsafe { ShellExecuteExW(&mut info) }.is_ok();

    if !started {
        // Самый частый исход — «Нет» в окне UAC. Отличить его от настоящей
        // ошибки нечем, да и незачем: и то и другое означает «не получилось».
        return Ok(false);
    }

    let process = HANDLE(info.hProcess.0);
    #[allow(unsafe_code, reason = "ожидание запущенного процесса")]
    let finished =
        unsafe { windows::Win32::System::Threading::WaitForSingleObject(process, WAIT_TIMEOUT_MS) };
    #[allow(unsafe_code, reason = "закрытие описателя процесса")]
    unsafe {
        let _ = CloseHandle(process);
    }

    Ok(finished == WAIT_OBJECT_0)
}

/// Собирает аргументы в одну строку командной строки.
///
/// Windows передаёт их именно так — одной строкой, — и разбирает обратно уже
/// поднятый процесс. Поэтому аргумент с пробелом обязан быть в кавычках:
/// иначе путь пользователя, в котором пробел есть почти всегда, распадётся на
/// два аргумента, и служба встанет не для того каталога настроек.
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
        // Путь пользователя почти всегда содержит пробел.
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
