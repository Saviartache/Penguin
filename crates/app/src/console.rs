//! Подключение к консоли родителя.
//!
//! Оконная программа консоли не имеет, и без подключения `penguin doctor` в
//! терминале печатал бы в пустоту.

/// Подключает вывод к консоли родителя, если писать больше некуда.
///
/// Перенаправленный вывод (`> out.txt`, `| findstr`) не трогает.
#[cfg(windows)]
pub fn attach_to_parent() {
    use windows::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole};

    if has_output() {
        return;
    }

    #[allow(unsafe_code, reason = "подключение к консоли родительского процесса")]
    let attached = unsafe { AttachConsole(ATTACH_PARENT_PROCESS) }.is_ok();

    if attached {
        // Описатели потоков остались от несуществующей консоли.
        reopen();
    }
}

/// Есть ли у процесса рабочий стандартный вывод.
#[cfg(windows)]
fn has_output() -> bool {
    use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows::Win32::System::Console::{GetStdHandle, STD_OUTPUT_HANDLE};

    #[allow(unsafe_code, reason = "чтение стандартного описателя процесса")]
    let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };

    match handle {
        Ok(handle) => !handle.is_invalid() && handle != INVALID_HANDLE_VALUE,
        Err(_) => false,
    }
}

/// Переоткрывает стандартные потоки на устройство консоли.
#[cfg(windows)]
fn reopen() {
    use std::os::windows::io::AsRawHandle;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Console::{STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle};

    let Ok(file) = std::fs::OpenOptions::new().write(true).open("CONOUT$") else {
        return;
    };
    let handle = HANDLE(file.as_raw_handle().cast());

    #[allow(unsafe_code, reason = "замена стандартных описателей на консольные")]
    unsafe {
        let _ = SetStdHandle(STD_OUTPUT_HANDLE, handle);
        let _ = SetStdHandle(STD_ERROR_HANDLE, handle);
    }

    // Описатель теперь и есть стандартный вывод.
    std::mem::forget(file);
}

/// На остальных системах программа и так консольная.
#[cfg(not(windows))]
pub fn attach_to_parent() {}
