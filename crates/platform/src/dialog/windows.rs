//! Windows: `IFileOpenDialog` (современное окно с боковой панелью и поиском; через COM).

#![allow(unsafe_code, reason = "окно выбора файла доступно только через COM")]

use std::path::PathBuf;

use windows::Win32::Foundation::{ERROR_CANCELLED, HWND};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoTaskMemFree, CoUninitialize,
};
use windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC;
use windows::Win32::UI::Shell::{
    FILEOPENDIALOGOPTIONS, FOS_FILEMUSTEXIST, FOS_FORCEFILESYSTEM, FOS_NOCHANGEDIR,
    FOS_PATHMUSTEXIST, FileOpenDialog, IFileOpenDialog, SIGDN_FILESYSPATH,
};
use windows::core::{HRESULT, HSTRING, PCWSTR};

use crate::error::{PlatformError, PlatformResult};

/// Маска исполняемых файлов.
const MASK: &str = "*.exe";

/// Только объекты с путём на диске, существующие; текущий каталог программы не двигать.
const OPTIONS: FILEOPENDIALOGOPTIONS = FILEOPENDIALOGOPTIONS(
    FOS_FORCEFILESYSTEM.0 | FOS_FILEMUSTEXIST.0 | FOS_PATHMUSTEXIST.0 | FOS_NOCHANGEDIR.0,
);

/// Показывает окно и ждёт ответа.
pub(super) fn pick_program(title: &str, filter: &str) -> PlatformResult<Option<PathBuf>> {
    // Объявлен первым — гаснет последним, после объектов COM.
    let _apartment = Apartment::enter();

    // SAFETY: COM поднят на этом потоке.
    let dialog: IFileOpenDialog =
        unsafe { CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER) }
            .map_err(|err| PlatformError::Dialog(format!("окно выбора не создалось: {err}")))?;

    let name = HSTRING::from(display_name(filter));
    let mask = HSTRING::from(MASK);
    let types = [COMDLG_FILTERSPEC {
        pszName: PCWSTR(name.as_ptr()),
        pszSpec: PCWSTR(mask.as_ptr()),
    }];

    // SAFETY: `name` и `mask` живут до конца функции.
    (|| unsafe {
        dialog.SetTitle(&HSTRING::from(title))?;
        dialog.SetFileTypes(&types)?;
        dialog.SetOptions(OPTIONS)
    })()
    .map_err(|err| PlatformError::Dialog(format!("окно выбора не настроилось: {err}")))?;

    // Без хозяина: описатель окна программы сюда не доходит.
    // SAFETY: `dialog` настроен.
    if let Err(err) = unsafe { dialog.Show(HWND::default()) } {
        // «Отмена» приходит как ошибка; отличается кодом (слова переведены).
        return if err.code() == HRESULT::from_win32(ERROR_CANCELLED.0) {
            Ok(None)
        } else {
            Err(PlatformError::Dialog(format!(
                "окно выбора не открылось: {err}"
            )))
        };
    }

    // SAFETY: окно закрыто с ответом.
    let item = unsafe { dialog.GetResult() }
        .map_err(|err| PlatformError::Dialog(format!("выбранный файл не назван: {err}")))?;
    // SAFETY: `item` — результат окна.
    let raw = unsafe { item.GetDisplayName(SIGDN_FILESYSPATH) }.map_err(|err| {
        PlatformError::Dialog(format!("путь к выбранному файлу не назван: {err}"))
    })?;

    // Строку выделил COM — он же освобождает её, до разбора результата.
    // SAFETY: `raw` — строка COM, освобождается ровно раз.
    let path = unsafe { raw.to_string() };
    unsafe { CoTaskMemFree(Some(raw.as_ptr().cast_const().cast())) };

    let path =
        path.map_err(|err| PlatformError::Dialog(format!("путь читается не как текст: {err}")))?;
    Ok(Some(PathBuf::from(path)))
}

/// Подпись вида файлов; маска дописывается здесь (на других системах у программ расширения нет).
fn display_name(filter: &str) -> String {
    format!("{filter} ({MASK})")
}

/// COM, поднятый на этом потоке и гасимый здесь же: поток из пула достаётся другой работе.
struct Apartment {
    /// Поднял его мы; чужой гасить нельзя.
    entered: bool,
}

impl Apartment {
    /// Поднимает COM (однопоточная модель — её ждёт оболочка).
    fn enter() -> Self {
        // SAFETY: вызов без указателей.
        let result = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        Self {
            entered: result.is_ok(),
        }
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.entered {
            // SAFETY: парный к успешному `CoInitializeEx`.
            unsafe { CoUninitialize() };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_kind_carries_its_mask() {
        assert_eq!(display_name("Программы"), "Программы (*.exe)");
    }

    #[test]
    fn com_lives_no_longer_than_the_window() {
        let apartment = Apartment::enter();
        drop(apartment);
    }
}
