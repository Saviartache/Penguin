//! Запуск службы правами пользователя окна. Разрешение даётся один раз, при установке с правами
//! администратора, и хранит его сама система: DACL службы (Windows), правило polkit (Linux),
//! каталог запроса launchd (macOS). Пароль после этого не спрашивается.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(target_os = "linux", test))]
mod polkit;
#[cfg(windows)]
mod windows;

use crate::error::PlatformResult;

/// Разрешает пользователю окна запускать службу; нужны права, повторный вызов безвреден.
pub fn allow(controller_uid: Option<u32>) -> PlatformResult<()> {
    #[cfg(windows)]
    {
        let _ = controller_uid;
        windows::allow()
    }
    #[cfg(target_os = "linux")]
    {
        linux::allow(controller_uid)
    }
    #[cfg(target_os = "macos")]
    {
        macos::allow(controller_uid)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = controller_uid;
        Err(crate::error::PlatformError::Unsupported(
            "запуск службы без прав",
        ))
    }
}

/// Запускает службу без прав администратора; `PermissionDenied` — разрешения ещё нет.
pub fn request() -> PlatformResult<()> {
    #[cfg(windows)]
    {
        crate::service::windows::start()
    }
    #[cfg(target_os = "linux")]
    {
        linux::request()
    }
    #[cfg(target_os = "macos")]
    {
        macos::request()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Err(crate::error::PlatformError::Unsupported(
            "запуск службы без прав",
        ))
    }
}

/// Снимает запрос перед штатным выходом службы, иначе launchd поднимет её снова.
pub fn withdraw() -> PlatformResult<()> {
    #[cfg(target_os = "macos")]
    {
        macos::withdraw()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
}
