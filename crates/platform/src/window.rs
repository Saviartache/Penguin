//! Рабочая область монитора окна Windows.

#![allow(unsafe_code, reason = "чтение геометрии окна через Win32")]

use windows::Win32::Foundation::HWND;
use windows::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromWindow,
};

use crate::{PlatformError, PlatformResult};

/// Рабочая область текущего монитора: `(x, y, ширина, высота)` в физических пикселах.
pub fn work_area(window: isize) -> PlatformResult<(i32, i32, u32, u32)> {
    let mut info = MONITORINFO {
        cbSize: size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: HWND только читается; `info` имеет размер MONITORINFO.
    let found = unsafe {
        let monitor = MonitorFromWindow(HWND(window as *mut _), MONITOR_DEFAULTTONEAREST);
        GetMonitorInfoW(monitor, &mut info)
    };
    if !found.as_bool() {
        return Err(PlatformError::Io(std::io::Error::last_os_error()));
    }
    let area = info.rcWork;
    Ok((
        area.left,
        area.top,
        (area.right - area.left) as u32,
        (area.bottom - area.top) as u32,
    ))
}
