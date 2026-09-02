//! Иконка исполняемого файла для GUI. За фичей: тянет графические зависимости.
//!
//! Нужна одному экрану — выбору приложений. Отсутствие иконки не мешает
//! ничему: интерфейс рисует заглушку.

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
