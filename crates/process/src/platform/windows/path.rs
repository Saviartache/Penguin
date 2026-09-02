//! `QueryFullProcessImageName` и приведение пути к каноническому виду.
//!
//! Именно `QueryFullProcessImageNameW`, а не `GetModuleFileNameEx`: первый
//! требует лишь `PROCESS_QUERY_LIMITED_INFORMATION` и потому работает для
//! процессов другого пользователя и для служб, а второй требует прав, которых
//! у клиента может не быть. Разница видна сразу: без неё половина системных
//! процессов остаётся без пути, и правила на них не действуют.

#![allow(unsafe_code, reason = "системные вызовы Windows")]

use windows::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

use crate::identity::ProcessIdentity;

/// Путь к исполняемому файлу процесса.
///
/// `None` — процесс уже завершился или доступ запрещён. И то и другое
/// нормально: между чтением таблицы и этим вызовом проходит время.
pub fn path_of(pid: u32) -> Option<String> {
    if pid == 0 {
        // Нулевой номер принадлежит псевдопроцессу простоя — открывать его
        // нечего.
        return None;
    }

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let path = read_path(handle);
    // Дескриптор закрывается в любом случае: утечка здесь копится по одному
    // на каждое новое соединение.
    unsafe { CloseHandle(handle) }.ok()?;
    path
}

fn read_path(handle: HANDLE) -> Option<String> {
    // Путь может быть длиннее MAX_PATH; запас берётся сразу, чтобы не
    // повторять вызов.
    let mut buffer = vec![0u16; MAX_PATH as usize * 4];
    let mut len = buffer.len() as u32;

    unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
    }
    .ok()?;

    buffer.truncate(len as usize);
    Some(String::from_utf16_lossy(&buffer))
}

/// Личность процесса по его номеру.
pub fn identity_of(pid: u32) -> Option<ProcessIdentity> {
    Some(ProcessIdentity::new(pid, path_of(pid)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_our_own_path() {
        let ours = std::process::id();
        let path = path_of(ours).expect("свой путь известен");
        assert!(
            path.to_lowercase().ends_with(".exe"),
            "неожиданный путь: {path}"
        );
    }

    #[test]
    fn identity_is_normalized() {
        let identity = identity_of(std::process::id()).expect("своя личность известна");
        assert!(
            !identity.path.contains('\\'),
            "разделители не нормализованы: {}",
            identity.path
        );
        assert_eq!(&*identity.path, identity.path.to_lowercase());
        assert!(identity.name.ends_with(".exe"));
    }

    #[test]
    fn missing_process_is_not_an_error() {
        // Ноль — псевдопроцесс простоя; номер из будущего почти наверняка
        // свободен. Ни то ни другое не должно ронять клиент.
        assert!(path_of(0).is_none());
        assert!(path_of(u32::MAX - 1).is_none());
    }
}
