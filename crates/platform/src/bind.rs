//! Привязка сокета к интерфейсу — то, чем клиент защищает от тоннеля своё
//! собственное соединение с сервером.
//!
//! # Почему адреса мало
//!
//! Привязать сокет к адресу физического интерфейса (`bind`) — значит выбрать
//! **обратный** адрес в пакете. Куда пакет поедет, решает не он, а таблица
//! маршрутизации, и после подъёма тоннеля она отправляет наружу всё подряд
//! через TUN. Сокет клиента до его же сервера уезжает в тоннель, который этот
//! сокет и должен поднять; снаружи это выглядит как «рукопожатие не
//! завершилось: timed out».
//!
//! Поэтому сокет привязывается к самому интерфейсу. Это отдельная возможность
//! системы, и она таблицу маршрутизации обходит.
//!
//! | система | как это называется |
//! |---------|--------------------|
//! | macOS   | `IP_BOUND_IF` / `IPV6_BOUND_IF` |
//! | Linux   | `SO_BINDTODEVICE`  |
//! | Windows | `IP_UNICAST_IF` / `IPV6_UNICAST_IF` |
//!
//! То же самое делает `VpnService.protect` в Android — там это единственный
//! способ, и назван он честнее всего: сокет **защищают** от своего тоннеля.
//!
//! # Почему не только маршрут до сервера
//!
//! Маршрут до сервера мимо тоннеля клиент ставит тоже (`route::pin_outside`),
//! и одно другого не заменяет. Маршрут требует знать адрес сервера заранее: имя
//! надо разрешить **до** подъёма тоннеля, а разрешение уже может не работать —
//! например, когда от прошлого запуска остался чужой маршрут по умолчанию.
//! Привязка к интерфейсу не требует знать ничего и работает, даже когда у
//! сервера сменился адрес.

use crate::error::{PlatformError, PlatformResult};

/// Привязывает сокет к интерфейсу с этим номером.
///
/// `ipv6` выбирает уровень параметра: у двух семейств он разный, и заданный не
/// тем уровнем параметр система молча не применит.
#[cfg(unix)]
pub fn to_interface(socket: std::os::fd::RawFd, index: u32, ipv6: bool) -> PlatformResult<()> {
    if index == 0 {
        return Err(PlatformError::Interface(
            "интерфейс без номера — привязывать не к чему".to_owned(),
        ));
    }
    set_option(socket, index, ipv6)
}

/// Привязывает сокет к интерфейсу с этим номером.
#[cfg(windows)]
pub fn to_interface(
    socket: std::os::windows::io::RawSocket,
    index: u32,
    ipv6: bool,
) -> PlatformResult<()> {
    if index == 0 {
        return Err(PlatformError::Interface(
            "интерфейс без номера — привязывать не к чему".to_owned(),
        ));
    }
    set_option(socket, index, ipv6)
}

/// macOS: `IP_BOUND_IF` берёт номер интерфейса как есть.
#[cfg(target_os = "macos")]
#[allow(unsafe_code, reason = "параметр сокета задаётся только так")]
fn set_option(socket: std::os::fd::RawFd, index: u32, ipv6: bool) -> PlatformResult<()> {
    let (level, name) = if ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    } else {
        (libc::IPPROTO_IP, libc::IP_BOUND_IF)
    };

    let value = index as libc::c_uint;
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

/// Linux: `SO_BINDTODEVICE` берёт **имя** интерфейса, а не номер.
///
/// Права на него нужны те же, что и на всё остальное в службе, — она и так
/// работает от системы.
#[cfg(target_os = "linux")]
#[allow(unsafe_code, reason = "параметр сокета задаётся только так")]
fn set_option(socket: std::os::fd::RawFd, index: u32, _ipv6: bool) -> PlatformResult<()> {
    // Имя восстанавливается по номеру: номер у нас уже есть от поиска пути
    // наружу, а `SO_BINDTODEVICE` понимает только имя.
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
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

/// Windows: `IP_UNICAST_IF`, и номер для IPv4 идёт в сетевом порядке байт.
///
/// Порядок — не описка и не украшение: у IPv4 этот параметр объявлен как адрес,
/// и система ждёт его перевёрнутым. У IPv6 — как номер, и переворачивать не
/// надо. Ошибка здесь означает привязку к несуществующему интерфейсу.
#[cfg(windows)]
#[allow(unsafe_code, reason = "параметр сокета задаётся только так")]
fn set_option(
    socket: std::os::windows::io::RawSocket,
    index: u32,
    ipv6: bool,
) -> PlatformResult<()> {
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

    let code = unsafe { setsockopt(SOCKET(socket as usize), level, name, Some(&bytes)) };
    check(code)
}

/// Никакой другой системы у клиента нет.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn set_option(_socket: std::os::fd::RawFd, _index: u32, _ipv6: bool) -> PlatformResult<()> {
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
        // Ноль означает «система интерфейс не назвала». Привязка к нему тихо
        // ничего не сделала бы, и сокет ушёл бы в тоннель — то есть ровно
        // туда, от чего привязка и защищает.
        #[cfg(unix)]
        let result = to_interface(-1, 0, false);
        #[cfg(windows)]
        let result = to_interface(0, 0, false);

        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_real_socket_binds_to_the_loopback() {
        // Петля есть на любой машине, и номер у неё всегда первый.
        use std::os::fd::AsRawFd;

        let Some(index) = std::num::NonZeroU32::new(unsafe_index("lo0").max(unsafe_index("lo")))
        else {
            return;
        };

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("сокет заводится");
        // Привязка к интерфейсу — привилегированная не везде; отказ по правам
        // здесь законен, а вот «параметра такого нет» — нет.
        if let Err(err) = to_interface(socket.as_raw_fd(), index.get(), false) {
            assert!(
                !err.to_string().contains("Protocol not available"),
                "система не знает параметра: {err}"
            );
        }
    }

    /// Номер интерфейса по имени. Ноль — такого имени нет.
    #[cfg(unix)]
    fn unsafe_index(name: &str) -> u32 {
        let Ok(name) = std::ffi::CString::new(name) else {
            return 0;
        };
        #[allow(unsafe_code, reason = "перевод имени интерфейса в номер")]
        unsafe {
            libc::if_nametoindex(name.as_ptr())
        }
    }
}
