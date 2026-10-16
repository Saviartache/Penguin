//! Windows: COM на время вызова оболочки (окно выбора файла, запуск с правами).

#![allow(unsafe_code, reason = "COM поднимается только через системный вызов")]

use windows::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
};

/// COM, поднятый на этом потоке и гасимый здесь же: поток из пула достаётся другой работе.
pub(crate) struct Apartment {
    /// Поднял его мы; чужой гасить нельзя.
    entered: bool,
}

impl Apartment {
    /// Поднимает COM (однопоточная модель без DDE — её ждёт оболочка).
    pub(crate) fn enter() -> Self {
        // SAFETY: вызов без указателей.
        let result =
            unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
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
    fn com_lives_no_longer_than_the_caller() {
        let apartment = Apartment::enter();
        drop(apartment);
    }
}
