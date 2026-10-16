//! Windows: ветка автозапуска текущего пользователя.

#![allow(unsafe_code, reason = "работа с реестром")]

use std::path::Path;

use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_SZ, RegCloseKey, RegDeleteValueW,
    RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};
use windows::core::{PCWSTR, w};

use super::ENTRY_NAME;
use crate::error::{PlatformError, PlatformResult};

/// Ветка автозапуска текущего пользователя.
const RUN_KEY: PCWSTR = w!(r"Software\Microsoft\Windows\CurrentVersion\Run");

/// Записывает команду в автозапуск.
pub(super) fn write(executable: &Path) -> PlatformResult<()> {
    let key = open(KEY_WRITE)?;

    let value: Vec<u16> = command(executable)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let name = wide(ENTRY_NAME);

    // SAFETY: `value` живёт до конца функции; длина в байтах вдвое больше числа `u16`.
    let bytes = unsafe { std::slice::from_raw_parts(value.as_ptr().cast::<u8>(), value.len() * 2) };
    // SAFETY: `key` открыт, `name` завершён нулём.
    let result = unsafe { RegSetValueExW(key, PCWSTR(name.as_ptr()), 0, REG_SZ, Some(bytes)) };
    // SAFETY: `key` открыт выше и закрывается ровно раз.
    let _ = unsafe { RegCloseKey(key) };

    result
        .ok()
        .map_err(|e| PlatformError::Service(format!("автозапуск: {e}")))
}

/// Убирает запись; отсутствующая — успех.
pub(super) fn remove() -> PlatformResult<()> {
    let key = open(KEY_WRITE)?;
    let name = wide(ENTRY_NAME);

    // SAFETY: `key` открыт, `name` завершён нулём.
    let result = unsafe { RegDeleteValueW(key, PCWSTR(name.as_ptr())) };
    // SAFETY: закрывается ровно раз.
    let _ = unsafe { RegCloseKey(key) };

    if result == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    result
        .ok()
        .map_err(|e| PlatformError::Service(format!("автозапуск: {e}")))
}

/// Читает текущее значение.
pub(super) fn read() -> Option<String> {
    let key = open(KEY_READ).ok()?;
    let name = wide(ENTRY_NAME);

    let mut size = 0u32;
    // SAFETY: запрос размера; `key` открыт, `name` завершён нулём.
    let probe = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(name.as_ptr()),
            None,
            None,
            None,
            Some(&mut size),
        )
    };
    if probe.is_err() || size == 0 {
        // SAFETY: закрывается ровно раз.
        let _ = unsafe { RegCloseKey(key) };
        return None;
    }

    let mut buffer = vec![0u8; size as usize];
    // SAFETY: буфер длиной `size` байт.
    let result = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(name.as_ptr()),
            None,
            None,
            Some(buffer.as_mut_ptr()),
            Some(&mut size),
        )
    };
    // SAFETY: закрывается ровно раз.
    let _ = unsafe { RegCloseKey(key) };
    result.ok().ok()?;

    // UTF-16; завершающий ноль в строку не входит.
    let wide: Vec<u16> = buffer
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_ne_bytes(*pair))
        .take_while(|unit| *unit != 0)
        .collect();
    Some(String::from_utf16_lossy(&wide))
}

fn open(access: windows::Win32::System::Registry::REG_SAM_FLAGS) -> PlatformResult<HKEY> {
    let mut key = HKEY::default();
    // SAFETY: `key` — локальный выходной параметр.
    unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, RUN_KEY, 0, access, &mut key) }
        .ok()
        .map_err(|e| PlatformError::Service(format!("ветка автозапуска: {e}")))?;
    Ok(key)
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Команда автозапуска: путь в кавычках (пробел в каталоге), аргументы — за кавычками.
fn command(executable: &Path) -> String {
    let mut command = format!("\"{}\"", executable.display());
    for argument in super::ARGUMENTS {
        command.push(' ');
        command.push_str(argument);
    }
    command
}

#[cfg(test)]
mod tests {
    use super::super::{disable, enable, is_enabled};
    use super::*;

    #[test]
    fn round_trips_through_the_registry() {
        // Один тест: запись общая для процесса, параллельные затирали бы друг друга.
        let executable = std::env::current_exe().expect("свой путь известен");

        enable(&executable).expect("включается");
        assert!(is_enabled(), "запись не появилась");

        let value = read().expect("значение читается");
        assert!(value.starts_with('"'), "путь без кавычек: {value}");
        assert!(value.ends_with(" --tray"), "запуск без значка: {value}");

        disable().expect("выключается");
        assert!(!is_enabled(), "запись осталась");

        // Повторное выключение ошибкой быть не должно.
        disable().expect("повторное выключение");
    }
}
