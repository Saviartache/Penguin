//! Иконка исполняемого файла для GUI (фича `icon`).

/// Иконка исполняемого файла в виде PNG.
#[cfg(feature = "icon")]
pub fn icon_of(path: &str) -> Option<Vec<u8>> {
    #[cfg(windows)]
    {
        crate::platform::windows::icon::icon_of(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}
