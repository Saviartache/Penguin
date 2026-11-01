//! Сдвиг системного курсора: кнопка, уехавшая вместе со строкой, остаётся под ним.

#![allow(unsafe_code, reason = "положение курсора через CoreGraphics и Win32")]

use crate::{PlatformError, PlatformResult};

/// Сдвигает курсор по вертикали на `dy` логических точек; `scale` — масштаб окна.
pub fn shift(dy: f32, scale: f32) -> PlatformResult<()> {
    #[cfg(target_os = "macos")]
    {
        let _ = scale;
        macos::shift(f64::from(dy))
    }
    #[cfg(windows)]
    {
        windows::shift((dy * scale).round() as i32)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = (dy, scale);
        Err(PlatformError::Unsupported("сдвиг курсора"))
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::c_void;

    use super::{PlatformError, PlatformResult};

    #[repr(C)]
    struct CGPoint {
        x: f64,
        y: f64,
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGEventCreate(source: *const c_void) -> *mut c_void;
        fn CGEventGetLocation(event: *mut c_void) -> CGPoint;
        fn CGWarpMouseCursorPosition(point: CGPoint) -> i32;
        fn CGAssociateMouseAndMouseCursorPosition(connected: i32) -> i32;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFRelease(object: *const c_void);
    }

    /// Точки CoreGraphics — те же логические точки, начало сверху слева.
    pub(super) fn shift(dy: f64) -> PlatformResult<()> {
        // SAFETY: пустое событие создаётся и освобождается здесь же.
        let point = unsafe {
            let event = CGEventCreate(std::ptr::null());
            if event.is_null() {
                return Err(PlatformError::Cursor("CGEventCreate".to_owned()));
            }
            let location = CGEventGetLocation(event);
            CFRelease(event);
            location
        };
        // SAFETY: функции без указателей.
        let code = unsafe {
            match CGWarpMouseCursorPosition(CGPoint {
                x: point.x,
                y: point.y + dy,
            }) {
                // Иначе мышь глохнет на четверть секунды и щелчки теряются.
                0 => CGAssociateMouseAndMouseCursorPosition(1),
                code => code,
            }
        };
        match code {
            0 => Ok(()),
            code => Err(PlatformError::Cursor(format!("CGError {code}"))),
        }
    }
}

#[cfg(windows)]
mod windows {
    use windows::Win32::Foundation::POINT;
    use windows::Win32::UI::WindowsAndMessaging::{GetCursorPos, SetCursorPos};

    use super::{PlatformError, PlatformResult};

    /// Физические пикселы; `SetCursorPos` сам шлёт окну `WM_MOUSEMOVE`.
    pub(super) fn shift(dy: i32) -> PlatformResult<()> {
        let mut point = POINT::default();
        // SAFETY: `point` живёт до конца вызова.
        unsafe {
            GetCursorPos(&mut point)
                .and_then(|()| SetCursorPos(point.x, point.y + dy))
                .map_err(|error| PlatformError::Cursor(error.to_string()))
        }
    }
}
