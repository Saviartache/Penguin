//! Подключение к консоли родителя.
//!
//! Файл собран как **оконный** — иначе двойной щелчок открывал бы рядом с
//! интерфейсом чёрное окно консоли, которое человек не просил и закрыть не
//! может, не закрыв программу.
//!
//! Плата за это: у оконной программы своей консоли нет, и `penguin doctor`,
//! запущенный из терминала, печатал бы в пустоту — команда отработала бы молча
//! и выглядела бы сломанной. Лечится подключением к консоли **родителя**.
//!
//! # Чего делать нельзя
//!
//! Подменять стандартный вывод **безусловно**. Если программу запустили с
//! перенаправлением (`penguin doctor > out.txt`, `penguin doctor | findstr`,
//! запуск из скрипта), вывод уже подключён к каналу или файлу — и подмена его
//! на консоль отправляет результат не туда, куда просили. Снаружи это
//! выглядит как команда, которая молча ничего не выводит.
//!
//! Поэтому сначала спрашивается, есть ли уже куда писать, и только если нет —
//! ищется консоль родителя.

/// Подключает вывод к консоли родителя, если писать больше некуда.
///
/// Ничего не делает в двух случаях, и оба нормальные: вывод уже перенаправлен
/// (тогда трогать его нельзя) или родительской консоли нет вовсе — это
/// обычный двойной щелчок.
#[cfg(windows)]
pub fn attach_to_parent() {
    use windows::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole};

    // Уже есть куда писать — значит, вывод перенаправили, и это чужое
    // решение.
    if has_output() {
        return;
    }

    #[allow(unsafe_code, reason = "подключение к консоли родительского процесса")]
    let attached = unsafe { AttachConsole(ATTACH_PARENT_PROCESS) }.is_ok();

    if attached {
        // Подключения мало: у потоков остались описатели прежней
        // (несуществующей) консоли, и печать в них уходит в никуда.
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
        // У оконной программы, запущенной щелчком, описателя нет вовсе.
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

    // Файл намеренно не закрывается: его описатель теперь и есть стандартный
    // вывод программы, и закрыть его значит закрыть вывод.
    std::mem::forget(file);
}

/// На остальных системах программа и так консольная.
#[cfg(not(windows))]
pub fn attach_to_parent() {}
