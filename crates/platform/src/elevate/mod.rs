//! Перезапуск себя с правами администратора: UAC на Windows, polkit на Linux, окно системы на
//! macOS. Просить только там, где права нужны (служба); лишний запрос приучает соглашаться вслепую.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

use crate::error::PlatformResult;

/// Запускает себя же с правами администратора и ждёт завершения; `Ok(false)` — человек отказался.
///
/// Аргументы передаются без кавычек: их ставит та система, которой это нужно (Windows).
pub fn run_elevated(args: &[&str]) -> PlatformResult<bool> {
    #[cfg(windows)]
    {
        windows::run_elevated(args)
    }
    #[cfg(target_os = "linux")]
    {
        linux::run_elevated(args)
    }
    #[cfg(target_os = "macos")]
    {
        macos::run_elevated(args)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = args;
        Err(crate::error::PlatformError::Unsupported("повышение прав"))
    }
}
