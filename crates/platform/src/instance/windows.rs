//! Именованный мьютекс: существует, пока жив хоть один дескриптор; владеть им не нужно.

use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
use windows::Win32::System::Threading::CreateMutexW;
use windows::core::HSTRING;

use super::lock::Instance;
use crate::error::{PlatformError, PlatformResult};

/// Дескриптор мьютекса; закрывается при уничтожении.
#[derive(Debug)]
pub(super) struct Held(HANDLE);

// SAFETY: дескриптор мьютекса можно закрыть из любого потока.
#[allow(unsafe_code, reason = "дескриптор ядра")]
unsafe impl Send for Held {}

impl Drop for Held {
    #[allow(unsafe_code, reason = "закрытие дескриптора")]
    fn drop(&mut self) {
        // SAFETY: дескриптор открыт в `try_lock` и закрывается ровно раз.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[allow(unsafe_code, reason = "создание мьютекса")]
pub(super) fn try_lock(instance: Instance, _dir: &Path) -> PlatformResult<Option<Held>> {
    let name = HSTRING::from(instance.mutex_name());
    // SAFETY: имя живёт до конца вызова; атрибуты безопасности по умолчанию.
    let handle = unsafe { CreateMutexW(None, false, &name) }
        .map_err(|err| PlatformError::Service(format!("мьютекс {}: {err}", instance.label())))?;
    // SAFETY: читается сразу после `CreateMutexW` в том же потоке.
    let exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;

    let held = Held(handle);
    // Занято: свой дескриптор закрывает `Drop`, чужой остаётся.
    Ok((!exists).then_some(held))
}
