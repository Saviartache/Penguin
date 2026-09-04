//! `proc_pidfdinfo` — владелец сокета.
//!
//! Ответ на вопрос «чей это порт» macOS даёт только перебором: список
//! процессов, у каждого список дескрипторов, у каждого сокета — его локальный
//! адрес. Дешевле не даёт никто: интерфейса «кому принадлежит порт» в системе
//! нет.
//!
//! # Про раскладку
//!
//! `struct socket_fdinfo` из `<sys/proc_info.h>` — часть открытого интерфейса
//! системы, и поля в нём не двигаются. Повторять его в Rust целиком значило бы
//! объявить пять вложенных структур ради четырёх чисел, поэтому ответ читается
//! по смещениям. Проверка при этом остаётся: система сообщает, сколько байт
//! записала, и ответ другого размера мы не разбираем вовсе.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Спросить у процесса список его дескрипторов.
const PROC_PIDFDSOCKETINFO: libc::c_int = 3;

/// Размер `struct socket_fdinfo`. Им же проверяется, что раскладка не уехала.
const SOCKET_FDINFO_SIZE: usize = 792;

/// Смещение `psi.soi_family`.
const SOI_FAMILY: usize = 184;
/// Смещение `psi.soi_kind`.
const SOI_KIND: usize = 256;
/// Смещение `psi.soi_proto.pri_in.insi_lport`.
const INSI_LPORT: usize = 268;
/// Смещение `psi.soi_proto.pri_in.insi_vflag`.
const INSI_VFLAG: usize = 288;
/// Смещение `psi.soi_proto.pri_in.insi_laddr`.
///
/// Внутри — объединение: IPv6-адрес занимает все шестнадцать байт, а
/// IPv4-адрес лежит в последних четырёх.
const INSI_LADDR: usize = 312;

/// Сокет из семейства интернета. `SOCKINFO_IN`.
const SOCKINFO_IN: i32 = 1;
/// Сокет TCP. `SOCKINFO_TCP`.
///
/// Поля `in_sockinfo` у него лежат там же: в объединении оба варианта
/// начинаются с одного и того же.
const SOCKINFO_TCP: i32 = 2;

/// Адрес IPv4. `INI_IPV4`.
const INI_IPV4: u8 = 1;
/// Адрес IPv6. `INI_IPV6`.
const INI_IPV6: u8 = 2;

/// Все процессы системы.
pub(super) fn all_pids() -> Vec<u32> {
    #[allow(unsafe_code, reason = "список процессов у системы")]
    let needed = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if needed <= 0 {
        return Vec::new();
    }

    // С запасом: процессы появляются между двумя вызовами, и точный размер из
    // первого оказывается мал уже во втором.
    let capacity = usize::try_from(needed).unwrap_or(0) + 64;
    let mut pids = vec![0i32; capacity];

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        reason = "размер буфера заведомо помещается в c_int"
    )]
    let size = (capacity * std::mem::size_of::<i32>()) as libc::c_int;

    #[allow(unsafe_code, reason = "список процессов у системы")]
    let written = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast::<libc::c_void>(), size) };
    if written <= 0 {
        return Vec::new();
    }

    let count = usize::try_from(written).unwrap_or(0);
    pids.truncate(count);
    pids.into_iter()
        .filter(|pid| *pid > 0)
        .map(|pid| pid.unsigned_abs())
        .collect()
}

/// Путь к исполняемому файлу процесса.
pub(super) fn path_of(pid: u32) -> Option<String> {
    /// `PROC_PIDPATHINFO_MAXSIZE` — потолок длины пути в системе.
    const MAX_PATH: usize = 4 * 1024;

    let mut buffer = vec![0u8; MAX_PATH];

    #[allow(unsafe_code, reason = "путь процесса у системы")]
    let written = unsafe {
        libc::proc_pidpath(
            i32::try_from(pid).ok()?,
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            u32::try_from(MAX_PATH).ok()?,
        )
    };
    if written <= 0 {
        // Процесс закрылся или он чужой и читать его нам не дали. И то и
        // другое — обычное дело.
        return None;
    }

    buffer.truncate(usize::try_from(written).ok()?);
    String::from_utf8(buffer).ok()
}

/// Локальные адреса всех сокетов процесса.
pub(super) fn local_addresses(pid: u32) -> Vec<SocketAddr> {
    descriptors(pid)
        .into_iter()
        .filter(|descriptor| descriptor.proc_fdtype == socket_type())
        .filter_map(|descriptor| local_address(pid, descriptor.proc_fd))
        .collect()
}

/// Тип дескриптора, означающий сокет.
fn socket_type() -> u32 {
    #[allow(
        clippy::cast_sign_loss,
        reason = "константа типа дескриптора неотрицательна"
    )]
    {
        libc::PROX_FDTYPE_SOCKET as u32
    }
}

/// Дескрипторы процесса.
fn descriptors(pid: u32) -> Vec<libc::proc_fdinfo> {
    let Ok(pid) = i32::try_from(pid) else {
        return Vec::new();
    };

    #[allow(unsafe_code, reason = "список дескрипторов процесса")]
    let needed =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        return Vec::new();
    }

    let one = std::mem::size_of::<libc::proc_fdinfo>();
    let count = usize::try_from(needed).unwrap_or(0) / one + 32;
    let mut fds = vec![empty_descriptor(); count];

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        reason = "размер буфера заведомо помещается в c_int"
    )]
    let size = (count * one) as libc::c_int;

    #[allow(unsafe_code, reason = "список дескрипторов процесса")]
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr().cast::<libc::c_void>(),
            size,
        )
    };
    if written <= 0 {
        return Vec::new();
    }

    fds.truncate(usize::try_from(written).unwrap_or(0) / one);
    fds
}

/// Пустая запись о дескрипторе.
fn empty_descriptor() -> libc::proc_fdinfo {
    libc::proc_fdinfo {
        proc_fd: 0,
        proc_fdtype: 0,
    }
}

/// Локальный адрес сокета.
fn local_address(pid: u32, descriptor: i32) -> Option<SocketAddr> {
    let mut buffer = [0u8; SOCKET_FDINFO_SIZE];

    #[allow(unsafe_code, reason = "сведения о сокете у системы")]
    let written = unsafe {
        libc::proc_pidfdinfo(
            i32::try_from(pid).ok()?,
            descriptor,
            PROC_PIDFDSOCKETINFO,
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_possible_wrap,
                reason = "размер структуры заведомо помещается в c_int"
            )]
            {
                SOCKET_FDINFO_SIZE as libc::c_int
            },
        )
    };

    // Ответ другого размера означает, что раскладка разошлась с нашей, и
    // читать его по смещениям нельзя.
    if usize::try_from(written).ok()? != SOCKET_FDINFO_SIZE {
        return None;
    }

    parse(&buffer)
}

/// Разбирает ответ системы о сокете.
///
/// Свободная функция с тестом: смещение, съехавшее на четыре байта, даёт
/// правдоподобный, но чужой адрес — и правило применяется не к тому
/// приложению.
fn parse(info: &[u8; SOCKET_FDINFO_SIZE]) -> Option<SocketAddr> {
    let family = number(info, SOI_FAMILY);
    let kind = number(info, SOI_KIND);

    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        reason = "семейства адресов помещаются в i32"
    )]
    let (inet, inet6) = (libc::AF_INET, libc::AF_INET6);
    if family != inet && family != inet6 {
        // Локальные сокеты, каналы и всё прочее адреса не имеют.
        return None;
    }
    if kind != SOCKINFO_IN && kind != SOCKINFO_TCP {
        return None;
    }

    // Порт лежит в порядке байт сети внутри числа: разбирать его надо по
    // байтам, а не по значению.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "порт занимает младшие два байта"
    )]
    let port = u16::from_be_bytes((number(info, INSI_LPORT) as u16).to_ne_bytes());

    let address = match info[INSI_VFLAG] {
        INI_IPV4 => {
            // В объединении IPv4-адрес лежит в последних четырёх байтах.
            let octets: [u8; 4] = info
                .get(INSI_LADDR + 12..INSI_LADDR + 16)?
                .try_into()
                .ok()?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        INI_IPV6 => {
            let octets: [u8; 16] = info.get(INSI_LADDR..INSI_LADDR + 16)?.try_into().ok()?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        // Сокет ещё не привязан ни к какому адресу.
        _ => return None,
    };

    Some(SocketAddr::new(address, port))
}

/// Целое число по смещению.
fn number(info: &[u8; SOCKET_FDINFO_SIZE], offset: usize) -> i32 {
    let bytes = [
        info[offset],
        info[offset + 1],
        info[offset + 2],
        info[offset + 3],
    ];
    i32::from_ne_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Собирает ответ системы с нужными полями.
    fn info(kind: i32, vflag: u8, port: u16, address: &[u8]) -> [u8; SOCKET_FDINFO_SIZE] {
        let mut buffer = [0u8; SOCKET_FDINFO_SIZE];
        buffer[SOI_FAMILY..SOI_FAMILY + 4].copy_from_slice(&libc::AF_INET.to_ne_bytes());
        buffer[SOI_KIND..SOI_KIND + 4].copy_from_slice(&kind.to_ne_bytes());
        buffer[INSI_VFLAG] = vflag;
        // Порт лежит в порядке байт сети.
        buffer[INSI_LPORT..INSI_LPORT + 2].copy_from_slice(&port.to_be_bytes());
        buffer[INSI_LADDR + 12..INSI_LADDR + 12 + address.len().min(4)]
            .copy_from_slice(&address[..address.len().min(4)]);
        buffer
    }

    #[test]
    fn reads_an_ipv4_socket() {
        let parsed = parse(&info(SOCKINFO_TCP, INI_IPV4, 8080, &[127, 0, 0, 1]));
        assert_eq!(
            parsed,
            Some("127.0.0.1:8080".parse::<SocketAddr>().expect("адрес"))
        );
    }

    #[test]
    fn a_port_keeps_the_network_byte_order() {
        // Порт лежит в числе в порядке байт сети; разбор по значению дал бы
        // 36895 вместе 8080 — правдоподобное, но чужое соединение.
        let parsed = parse(&info(SOCKINFO_IN, INI_IPV4, 443, &[0, 0, 0, 0])).expect("адрес");
        assert_eq!(parsed.port(), 443);
    }

    #[test]
    fn a_socket_without_an_address_is_skipped() {
        // Сокет, ещё не привязанный ни к чему, владельцем порта не является.
        assert!(parse(&info(SOCKINFO_TCP, 0, 8080, &[0, 0, 0, 0])).is_none());
    }

    #[test]
    fn a_socket_of_another_kind_is_skipped() {
        // Локальные сокеты и каналы адреса не имеют, и разбирать их поля
        // значит читать чужую половину объединения.
        assert!(parse(&info(7, INI_IPV4, 8080, &[127, 0, 0, 1])).is_none());
    }

    #[test]
    fn we_can_see_our_own_socket() {
        // Сквозная проверка: сокет открыт этим самым процессом, и найтись
        // должен именно его адрес.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("сокет");
        let local = listener.local_addr().expect("адрес");

        let found = local_addresses(std::process::id());
        assert!(found.contains(&local), "свой сокет не найден: {found:?}");
    }

    #[test]
    fn our_own_path_is_known() {
        let path = path_of(std::process::id()).expect("путь известен");
        assert!(path.starts_with('/'), "{path}");
    }

    #[test]
    fn the_system_has_processes() {
        let pids = all_pids();
        assert!(pids.contains(&std::process::id()), "нас нет в списке");
    }
}
