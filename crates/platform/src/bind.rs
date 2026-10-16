//! Привязка сокета к интерфейсу: защищает соединение клиента с сервером от его же тоннеля.
//!
//! Привязка по адресу (`bind`) таблицу маршрутов не обходит — после подъёма тоннеля сокет уехал бы
//! в TUN. Привязка к самому интерфейсу обходит и не требует знать адрес сервера заранее.
//!
//! | система | параметр |
//! |---------|----------|
//! | macOS   | `IP_BOUND_IF` / `IPV6_BOUND_IF` |
//! | Linux   | `SO_BINDTODEVICE`  |
//! | Windows | `IP_UNICAST_IF` / `IPV6_UNICAST_IF` |

use crate::error::{PlatformError, PlatformResult};

#[cfg(unix)]
type RawSock = std::os::fd::RawFd;
#[cfg(windows)]
type RawSock = std::os::windows::io::RawSocket;

/// Привязывает сокет к интерфейсу с этим номером; `ipv6` выбирает уровень параметра.
pub fn to_interface(socket: RawSock, index: u32, ipv6: bool) -> PlatformResult<()> {
    if index == 0 {
        return Err(PlatformError::Interface(
            "интерфейс без номера — привязывать не к чему".to_owned(),
        ));
    }
    set_option(socket, index, ipv6)
}

/// macOS: `IP_BOUND_IF` берёт номер интерфейса.
#[cfg(target_os = "macos")]
#[allow(unsafe_code, reason = "параметр сокета задаётся только так")]
fn set_option(socket: RawSock, index: u32, ipv6: bool) -> PlatformResult<()> {
    let (level, name) = if ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    } else {
        (libc::IPPROTO_IP, libc::IP_BOUND_IF)
    };

    let value = index as libc::c_uint;
    // SAFETY: указатель и длина описывают локальное `value`.
    let code = unsafe {
        libc::setsockopt(
            socket,
            level,
            name,
            std::ptr::from_ref(&value).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    check(code)
}

/// Linux: `SO_BINDTODEVICE` берёт имя интерфейса, а не номер.
#[cfg(target_os = "linux")]
#[allow(unsafe_code, reason = "параметр сокета задаётся только так")]
fn set_option(socket: RawSock, index: u32, _ipv6: bool) -> PlatformResult<()> {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: буфер `IF_NAMESIZE` — то, чего требует `if_indextoname`.
    let resolved = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };
    if resolved.is_null() {
        return Err(PlatformError::Interface(format!(
            "интерфейс с номером {index} не назван системой"
        )));
    }

    let length = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    // SAFETY: `name` живёт до конца вызова, `length` не больше его размера.
    let code = unsafe {
        libc::setsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            length as libc::socklen_t,
        )
    };
    check(code)
}

/// Windows: `IP_UNICAST_IF`; номер IPv4 идёт в сетевом порядке байт, номер IPv6 — как есть.
#[cfg(windows)]
#[allow(unsafe_code, reason = "параметр сокета задаётся только так")]
fn set_option(socket: RawSock, index: u32, ipv6: bool) -> PlatformResult<()> {
    use windows::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, setsockopt,
    };

    let value = if ipv6 { index } else { index.to_be() };
    let bytes = value.to_ne_bytes();

    let (level, name) = if ipv6 {
        (IPPROTO_IPV6.0, IPV6_UNICAST_IF)
    } else {
        (IPPROTO_IP.0, IP_UNICAST_IF)
    };

    // SAFETY: `bytes` живёт до конца вызова.
    let code = unsafe { setsockopt(SOCKET(socket as usize), level, name, Some(&bytes)) };
    check(code)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn set_option(_socket: RawSock, _index: u32, _ipv6: bool) -> PlatformResult<()> {
    Err(PlatformError::Unsupported("привязка сокета к интерфейсу"))
}

/// Превращает код возврата в ошибку с причиной от системы.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn check(code: i32) -> PlatformResult<()> {
    if code == 0 {
        return Ok(());
    }
    Err(PlatformError::Interface(format!(
        "сокет не привязан к интерфейсу: {}",
        std::io::Error::last_os_error()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_interface_without_a_number_is_refused() {
        #[cfg(unix)]
        let result = to_interface(-1, 0, false);
        #[cfg(windows)]
        let result = to_interface(0, 0, false);

        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_real_socket_binds_to_the_loopback() {
        use std::os::fd::AsRawFd;

        let Some(index) = std::num::NonZeroU32::new(unsafe_index("lo0").max(unsafe_index("lo")))
        else {
            return;
        };

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("сокет заводится");
        // Отказ по правам законен, «параметра нет» — нет.
        if let Err(err) = to_interface(socket.as_raw_fd(), index.get(), false) {
            assert!(
                !err.to_string().contains("Protocol not available"),
                "система не знает параметра: {err}"
            );
        }
    }

    /// Номер интерфейса по имени; ноль — такого имени нет.
    #[cfg(unix)]
    fn unsafe_index(name: &str) -> u32 {
        let Ok(name) = std::ffi::CString::new(name) else {
            return 0;
        };
        #[allow(unsafe_code, reason = "перевод имени интерфейса в номер")]
        // SAFETY: `name` — валидная C-строка.
        unsafe {
            libc::if_nametoindex(name.as_ptr())
        }
    }
}
