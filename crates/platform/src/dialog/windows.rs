//! Windows: `IFileOpenDialog`.
//!
//! Не `GetOpenFileNameW`: тот показывает окно из времён Windows XP — без
//! боковой панели, без поиска и без быстрого доступа к недавним каталогам.
//! Человек, которого попросили найти `Steam.exe`, ищет его именно там.
//!
//! Плата — COM: окно выбора живёт в оболочке, а до оболочки другого пути нет.

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

/// Каким должен быть ответ окна.
///
/// `FORCEFILESYSTEM` — только то, у чего есть путь на диске: без него окно
/// отдаёт и «Этот компьютер», и библиотеки, и содержимое телефона, у которых
/// пути нет вовсе. `FILEMUSTEXIST` и `PATHMUSTEXIST` — правило на файл,
/// которого нет, не сработает никогда. `NOCHANGEDIR` — окно выбора не имеет
/// права двигать текущий каталог программы: по нему считаются относительные
/// пути всего остального.
const OPTIONS: FILEOPENDIALOGOPTIONS = FILEOPENDIALOGOPTIONS(
    FOS_FORCEFILESYSTEM.0 | FOS_FILEMUSTEXIST.0 | FOS_PATHMUSTEXIST.0 | FOS_NOCHANGEDIR.0,
);

/// Показывает окно и ждёт ответа.
pub(super) fn pick_program(title: &str, filter: &str) -> PlatformResult<Option<PathBuf>> {
    // Объявлен первым — гаснет последним: COM гасится после того, как
    // отпущены все взятые у него объекты.
    let _apartment = Apartment::enter();

    let dialog: IFileOpenDialog =
        unsafe { CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER) }
            .map_err(|err| PlatformError::Dialog(format!("окно выбора не создалось: {err}")))?;

    let name = HSTRING::from(display_name(filter));
    let mask = HSTRING::from(MASK);
    let types = [COMDLG_FILTERSPEC {
        pszName: PCWSTR(name.as_ptr()),
        pszSpec: PCWSTR(mask.as_ptr()),
    }];

    // Настройки одной связкой: порознь каждая давала бы своё сообщение об
    // ошибке, а человеку от них всех одинаково — окно не открылось.
    (|| unsafe {
        dialog.SetTitle(&HSTRING::from(title))?;
        dialog.SetFileTypes(&types)?;
        dialog.SetOptions(OPTIONS)
    })()
    .map_err(|err| PlatformError::Dialog(format!("окно выбора не настроилось: {err}")))?;

    // Хозяина у окна нет: окно программы своё, без системной рамки, и его
    // описатель до платформенного слоя не доходит. Системное окно от этого
    // становится отдельным — но всплывает поверх и остаётся на панели задач.
    if let Err(err) = unsafe { dialog.Show(HWND::default()) } {
        // «Отмена» приходит той же дорогой, что и поломка, и отличить их можно
        // только по коду: слова в сообщении переведены, а коды — нет.
        return if err.code() == HRESULT::from_win32(ERROR_CANCELLED.0) {
            Ok(None)
        } else {
            Err(PlatformError::Dialog(format!(
                "окно выбора не открылось: {err}"
            )))
        };
    }

    let item = unsafe { dialog.GetResult() }
        .map_err(|err| PlatformError::Dialog(format!("выбранный файл не назван: {err}")))?;
    let raw = unsafe { item.GetDisplayName(SIGDN_FILESYSPATH) }.map_err(|err| {
        PlatformError::Dialog(format!("путь к выбранному файлу не назван: {err}"))
    })?;

    // Строку выделил COM — освобождать её тоже ему, и до того, как мы решим,
    // что с ней делать: иначе она осталась бы висеть на любом неудачном пути.
    let path = unsafe { raw.to_string() };
    unsafe { CoTaskMemFree(Some(raw.as_ptr().cast_const().cast())) };

    let path =
        path.map_err(|err| PlatformError::Dialog(format!("путь читается не как текст: {err}")))?;
    Ok(Some(PathBuf::from(path)))
}

/// Как назван вид файлов в списке окна.
///
/// Маска дописывается здесь, а не в подписи интерфейса: на остальных системах
/// у программ расширения нет, и `(*.exe)` в переводе было бы враньём.
fn display_name(filter: &str) -> String {
    format!("{filter} ({MASK})")
}

/// Поднятый на этом потоке COM.
///
/// Поднимается и гасится здесь же. Поток под окно берётся из общего пула и
/// после нас достаётся другой работе — а работа, которой COM не нужен,
/// получила бы его в чужой модели и не поняла почему.
struct Apartment {
    /// Подняли его мы. Чужой гасить нельзя.
    entered: bool,
}

impl Apartment {
    /// Поднимает COM, если его на этом потоке ещё нет.
    fn enter() -> Self {
        // Однопоточная модель: окно выбора — часть оболочки, а оболочка ждёт
        // именно её.
        let result = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        Self {
            entered: result.is_ok(),
        }
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.entered {
            unsafe { CoUninitialize() };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_kind_carries_its_mask() {
        // Список видов файлов в окне Windows показывает ровно ту строку,
        // которую ему дали: без маски человек не поймёт, что ему предлагают.
        assert_eq!(display_name("Программы"), "Программы (*.exe)");
    }

    #[test]
    fn com_lives_no_longer_than_the_window() {
        // Поток берётся из общего пула: поднятый и не погашенный COM достался
        // бы следующей работе.
        let apartment = Apartment::enter();
        drop(apartment);
    }
}
