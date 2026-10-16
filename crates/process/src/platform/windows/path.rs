//! Путь процесса через `QueryFullProcessImageNameW`: ему хватает
//! `PROCESS_QUERY_LIMITED_INFORMATION`, в отличие от `GetModuleFileNameEx`.

#![allow(unsafe_code, reason = "системные вызовы Windows")]

use windows::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

use crate::identity::ProcessIdentity;

/// Путь к исполняемому файлу; `None` — процесс завершился или доступ запрещён.
pub fn path_of(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let path = read_path(handle);
    unsafe { CloseHandle(handle) }.ok()?;
    path
}

fn read_path(handle: HANDLE) -> Option<String> {
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
        assert!(path_of(0).is_none());
        assert!(path_of(u32::MAX - 1).is_none());
    }
}
