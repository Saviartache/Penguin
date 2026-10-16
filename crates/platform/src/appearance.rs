//! Windows: тема панели задач — по ней выбирается цвет значка в лотке.

#![allow(unsafe_code, reason = "чтение реестра")]

use windows::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
use windows::core::w;

/// Светлая ли панель задач. Нет значения — тёмная: так у Windows 10 по умолчанию.
pub fn light_taskbar() -> bool {
    let mut value = 0u32;
    let mut size = size_of::<u32>() as u32;
    // SAFETY: строки завершены нулём, `value` вмещает DWORD, `size` — его размер.
    let result = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            w!(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"),
            w!("SystemUsesLightTheme"),
            RRF_RT_REG_DWORD,
            None,
            Some((&raw mut value).cast()),
            Some(&mut size),
        )
    };
    result.is_ok() && value != 0
}
