//! Сброс чужих соединений TCP: открытые до тоннеля, они иначе живут мимо него, пока приложение
//! само их не пересоздаст. Сброшенное приложение сразу открывает новое — уже через тоннель.
//!
//! Linux — `SOCK_DESTROY` через `sock_diag`, Windows — `SetTcpEntry`. Обе — только IPv4: тоннель
//! забирает только его. У macOS такого интерфейса нет: там старое соединение сбрасывает стек
//! тоннеля на первом же его пакете.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "linux", test))]
mod sock_diag;
#[cfg(windows)]
mod windows;

use std::net::SocketAddrV4;

use crate::error::PlatformResult;

/// Сбрасывает установленные соединения TCP, чей удалённый адрес одобрил `selected`; возвращает,
/// сколько сброшено. Нужны права администратора.
pub fn reset_tcp(selected: &dyn Fn(SocketAddrV4) -> bool) -> PlatformResult<usize> {
    #[cfg(target_os = "linux")]
    {
        linux::reset_tcp(selected)
    }
    #[cfg(windows)]
    {
        windows::reset_tcp(selected)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = selected;
        Ok(0)
    }
}
