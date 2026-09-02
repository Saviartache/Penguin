//! Перезапуск самого себя с правами администратора.
//!
//! Права в Windows не выдаются процессу на ходу: их получает только новый
//! процесс, запущенный через `ShellExecuteW` с глаголом `runas` — то самое
//! окно UAC. Поэтому «получить права» здесь означает «запустить себя заново с
//! нужной командой и дождаться».
//!
//! Просить их должно не всё подряд, а ровно то, чему они нужны: установка
//! службы, её запуск и остановка. Окно и проверки работают без прав и
//! спрашивать их не должны — лишний запрос UAC приучает нажимать «Да», не
//! читая.

use crate::error::{PlatformError, PlatformResult};

/// Запускает себя же с правами администратора и ждёт завершения.
///
/// `Ok(false)` — пользователь отказался в окне UAC. Это не ошибка: он имел
/// право отказаться, и ругаться на него незачем.
#[cfg(windows)]
pub fn run_elevated(args: &[&str]) -> PlatformResult<bool> {
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
    let parameters = wide(&args.join(" "));

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

/// Сколько ждать поднятый процесс.
///
/// Установка службы вместе с окном UAC укладывается в секунды; полминуты —
/// с запасом на медленную машину и на человека, который отвлёкся. Дольше ждать
/// незачем: окно всё это время не отвечает.
#[cfg(windows)]
const WAIT_TIMEOUT_MS: u32 = 30_000;

/// На остальных системах повышение прав устроено иначе.
#[cfg(not(windows))]
pub fn run_elevated(_args: &[&str]) -> PlatformResult<bool> {
    Err(PlatformError::Unsupported(
        "повышение прав поддержано только на Windows",
    ))
}
