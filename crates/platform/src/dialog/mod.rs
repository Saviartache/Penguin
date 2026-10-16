//! Системное окно выбора файла: показать программу, которой нет среди запущенных.
//!
//! Вызов держит поток до ответа человека; из потока отрисовки его звать нельзя.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

use std::path::PathBuf;

use crate::error::PlatformResult;

/// Просит человека показать программу: `title` — заголовок окна, `filter` — подпись вида файлов
/// (обе приходят переведёнными из интерфейса). `Ok(None)` — окно закрыли без выбора.
pub fn pick_program(title: &str, filter: &str) -> PlatformResult<Option<PathBuf>> {
    #[cfg(windows)]
    {
        windows::pick_program(title, filter)
    }
    #[cfg(target_os = "linux")]
    {
        linux::pick_program(title, filter)
    }
    #[cfg(target_os = "macos")]
    {
        macos::pick_program(title, filter)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (title, filter);
        Err(crate::error::PlatformError::Unsupported("выбор файла"))
    }
}
