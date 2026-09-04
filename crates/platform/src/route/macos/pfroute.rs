//! Разговор с ядром через `PF_ROUTE`.
//!
//! Не `route add`: маршруты — то, чем тоннель забирает трафик, и снимать их
//! обязательно даже по аварийному пути. Зависеть в этом от чужой программы,
//! вывод которой к тому же переводится, нельзя.
//!
//! Сообщение устроено просто: заголовок, а за ним подряд адреса в порядке
//! битов в `rtm_addrs`. Каждый выровнен по четыре байта — так их читает ядро.

use std::net::IpAddr;
use std::os::fd::AsRawFd;

use crate::error::{PlatformError, PlatformResult};

/// Собираемое сообщение.
pub(super) struct Message {
    header: libc::rt_msghdr,
    addresses: Vec<u8>,
}

impl Message {
    /// Начинает сообщение указанного вида.
    pub(super) fn new(kind: u8, flags: libc::c_int) -> Self {
        Self {
            header: libc::rt_msghdr {
                rtm_msglen: 0,
                #[allow(
                    clippy::cast_sign_loss,
                    clippy::cast_possible_truncation,
                    reason = "версия протокола помещается в байт"
                )]
                rtm_version: libc::RTM_VERSION as u8,
                rtm_type: kind,
                rtm_index: 0,
                rtm_flags: flags,
                rtm_addrs: 0,
                rtm_pid: 0,
                rtm_seq: 0,
                rtm_errno: 0,
                rtm_use: 0,
                rtm_inits: 0,
                rtm_rmx: empty_metrics(),
            },
            addresses: Vec::with_capacity(64),
        }
    }

    /// Дописывает адрес.
    ///
    /// Порядок вызовов обязан совпадать с порядком битов в `rtm_addrs`:
    /// назначение, шлюз, маска. Ядро читает адреса подряд и разбирает их
    /// именно по этому порядку, а не по содержимому.
    pub(super) fn address(&mut self, slot: libc::c_int, bytes: &[u8]) {
        self.header.rtm_addrs |= slot;
        self.addresses.extend_from_slice(bytes);
        self.addresses.resize(align(self.addresses.len()), 0);
    }

    /// Проставляет длину и порядковый номер и отдаёт готовые байты.
    pub(super) fn finish(mut self, sequence: libc::c_int) -> Vec<u8> {
        let length = std::mem::size_of::<libc::rt_msghdr>() + self.addresses.len();

        #[allow(
            clippy::cast_possible_truncation,
            reason = "сообщение о маршруте заведомо короче 64 КиБ"
        )]
        {
            self.header.rtm_msglen = length as libc::c_ushort;
        }
        self.header.rtm_seq = sequence;

        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(bytes_of(&self.header));
        bytes.extend_from_slice(&self.addresses);
        bytes
    }
}

/// Пустые метрики маршрута: ядру они не нужны, а поля есть.
fn empty_metrics() -> libc::rt_metrics {
    libc::rt_metrics {
        rmx_locks: 0,
        rmx_mtu: 0,
        rmx_hopcount: 0,
        rmx_expire: 0,
        rmx_recvpipe: 0,
        rmx_sendpipe: 0,
        rmx_ssthresh: 0,
        rmx_rtt: 0,
        rmx_rttvar: 0,
        rmx_pksent: 0,
        rmx_state: 0,
        rmx_filler: [0; 3],
    }
}

/// Выравнивает длину по четыре байта.
const fn align(length: usize) -> usize {
    (length + 3) & !3
}

/// Байты структуры как они лягут в сообщение.
fn bytes_of<T: Copy>(value: &T) -> &[u8] {
    #[allow(unsafe_code, reason = "заголовок маршрута передаётся ядру как есть")]
    unsafe {
        std::slice::from_raw_parts(
            std::ptr::from_ref(value).cast::<u8>(),
            std::mem::size_of::<T>(),
        )
    }
}

/// Адрес в виде `sockaddr_in` / `sockaddr_in6`.
///
/// `sin_len` обязателен: в BSD длина лежит в самой структуре, и без неё ядро
/// прочитает адрес не той длины.
pub(super) fn sockaddr(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(v4) => {
            let mut bytes = vec![0u8; 16];
            bytes[0] = 16;
            #[allow(
                clippy::cast_sign_loss,
                clippy::cast_possible_truncation,
                reason = "семейство адресов помещается в байт"
            )]
            {
                bytes[1] = libc::AF_INET as u8;
            }
            bytes[4..8].copy_from_slice(&v4.octets());
            bytes
        }
        IpAddr::V6(v6) => {
            let mut bytes = vec![0u8; 28];
            bytes[0] = 28;
            #[allow(
                clippy::cast_sign_loss,
                clippy::cast_possible_truncation,
                reason = "семейство адресов помещается в байт"
            )]
            {
                bytes[1] = libc::AF_INET6 as u8;
            }
            bytes[8..24].copy_from_slice(&v6.octets());
            bytes
        }
    }
}

/// Интерфейс в виде `sockaddr_dl` — так задаётся маршрут «на интерфейс».
///
/// Длина восемь байт, а не двадцать: имени и аппаратного адреса у нас нет, а
/// ядру достаточно номера.
pub(super) fn sockaddr_link(interface_index: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; 8];
    bytes[0] = 8;
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        reason = "семейство адресов помещается в байт"
    )]
    {
        bytes[1] = libc::AF_LINK as u8;
    }
    #[allow(
        clippy::cast_possible_truncation,
        reason = "номер интерфейса помещается в u16"
    )]
    bytes[2..4].copy_from_slice(&(interface_index as u16).to_ne_bytes());
    bytes
}

/// Отправляет сообщение и, если попросили, читает ответ.
pub(super) fn talk(message: Message, expect_reply: bool) -> PlatformResult<Vec<u8>> {
    use nix::sys::socket::{AddressFamily, MsgFlags, SockFlag, SockType};

    let socket =
        nix::sys::socket::socket(AddressFamily::Route, SockType::Raw, SockFlag::empty(), None)
            .map_err(|err| PlatformError::Route(format!("сокет маршрутизации: {err}")))?;

    // Номер нужен, только чтобы отличить свой ответ от чужого: сокет
    // маршрутизации широковещательный, и в него сыплются чужие уведомления.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        reason = "от времени нужен лишь неповторяющийся хвост"
    )]
    let sequence = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |since| {
            (since.as_nanos() as u32 & 0x7FFF_FFFF) as libc::c_int
        });

    let request = message.finish(sequence);
    nix::sys::socket::send(socket.as_raw_fd(), &request, MsgFlags::empty()).map_err(classify)?;

    if !expect_reply {
        return Ok(Vec::new());
    }

    let ours = std::process::id();
    // Чужих уведомлений в сокете может быть сколько угодно; своё узнаётся по
    // номеру и по идентификатору процесса.
    for _ in 0..MAX_FOREIGN_MESSAGES {
        let mut reply = vec![0u8; 4096];
        let read = nix::sys::socket::recv(socket.as_raw_fd(), &mut reply, MsgFlags::empty())
            .map_err(classify)?;
        reply.truncate(read);

        if let Some((seq, pid, errno)) = identity(&reply)
            && seq == sequence
            && u32::try_from(pid) == Ok(ours)
        {
            if errno != 0 {
                return Err(PlatformError::Route(
                    std::io::Error::from_raw_os_error(errno).to_string(),
                ));
            }
            return Ok(reply);
        }
    }

    Err(PlatformError::Route(
        "ядро не ответило на запрос о маршруте".to_owned(),
    ))
}

/// Сколько чужих уведомлений пропустить, прежде чем сдаться.
const MAX_FOREIGN_MESSAGES: usize = 32;

/// Номер, процесс и код ошибки из заголовка ответа.
fn identity(reply: &[u8]) -> Option<(libc::c_int, libc::c_int, libc::c_int)> {
    if reply.len() < std::mem::size_of::<libc::rt_msghdr>() {
        return None;
    }
    // Смещения полей в `rt_msghdr`: процесс, номер, код ошибки идут подряд.
    let field = |offset: usize| {
        let bytes = reply.get(offset..offset + 4)?;
        Some(libc::c_int::from_ne_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]))
    };
    Some((field(20)?, field(16)?, field(24)?))
}

/// Переводит отказ ядра в ошибку с причиной.
fn classify(err: nix::errno::Errno) -> PlatformError {
    match err {
        nix::errno::Errno::EPERM | nix::errno::Errno::EACCES => {
            PlatformError::PermissionDenied("изменение таблицы маршрутизации".to_owned())
        }
        other => PlatformError::Route(other.to_string()),
    }
}

/// Перебирает адреса, приложенные к сообщению.
///
/// Возвращает пары «бит слота, байты адреса». Ответ ядра — чужие данные, и
/// обрыв в середине здесь обычное дело: перебор просто заканчивается.
pub(super) fn addresses(reply: &[u8]) -> Vec<(libc::c_int, &[u8])> {
    let head = std::mem::size_of::<libc::rt_msghdr>();
    let Some(slots) = reply.get(12..16) else {
        return Vec::new();
    };
    let slots = libc::c_int::from_ne_bytes([slots[0], slots[1], slots[2], slots[3]]);

    let mut found = Vec::new();
    let mut offset = head;

    for bit in 0..8 {
        let slot = 1 << bit;
        if slots & slot == 0 {
            continue;
        }
        let Some(&length) = reply.get(offset) else {
            break;
        };
        let length = if length == 0 { 4 } else { usize::from(length) };
        let Some(bytes) = reply.get(offset..offset + length) else {
            break;
        };
        found.push((slot, bytes));
        offset += align(length);
    }
    found
}

/// Номер интерфейса из заголовка ответа.
pub(super) fn interface_index(reply: &[u8]) -> u32 {
    reply.get(4..6).map_or(0, |bytes| {
        u32::from(u16::from_ne_bytes([bytes[0], bytes[1]]))
    })
}

/// Адрес из `sockaddr`.
pub(super) fn to_address(bytes: &[u8]) -> Option<IpAddr> {
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        reason = "семейство адресов помещается в байт"
    )]
    let (inet, inet6) = (libc::AF_INET as u8, libc::AF_INET6 as u8);

    match bytes.get(1).copied()? {
        family if family == inet => {
            let octets: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
            Some(IpAddr::from(octets))
        }
        family if family == inet6 => {
            let octets: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
            Some(IpAddr::from(octets))
        }
        // Шлюзом может быть и интерфейс (`AF_LINK`) — это не адрес.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_is_the_size_the_kernel_expects() {
        // Разойдясь с ядром на байт, мы получим `EINVAL` без единого намёка
        // на причину.
        assert_eq!(std::mem::size_of::<libc::rt_msghdr>(), 92);
    }

    #[test]
    fn addresses_are_aligned_to_four_bytes() {
        let mut message = Message::new(1, 0);
        message.address(libc::RTA_DST, &sockaddr("203.0.113.5".parse().expect("а")));
        message.address(libc::RTA_GATEWAY, &sockaddr_link(7));

        let bytes = message.finish(1);
        // Заголовок, шестнадцать байт адреса и восемь байт интерфейса.
        assert_eq!(bytes.len(), std::mem::size_of::<libc::rt_msghdr>() + 16 + 8);
    }

    #[test]
    fn a_length_travels_inside_the_address() {
        // В BSD длина лежит в самой структуре; ноль здесь означает адрес,
        // который ядро прочитает не так.
        assert_eq!(sockaddr("203.0.113.5".parse().expect("а"))[0], 16);
        assert_eq!(sockaddr("::1".parse().expect("а"))[0], 28);
        assert_eq!(sockaddr_link(7)[0], 8);
    }

    #[test]
    fn an_interface_gateway_is_not_an_address() {
        // Шлюзом маршрута «на интерфейс» стоит сам интерфейс; принять его за
        // адрес значит увести прямой трафик в никуда.
        assert!(to_address(&sockaddr_link(7)).is_none());
        assert_eq!(
            to_address(&sockaddr("203.0.113.5".parse().expect("а"))),
            Some("203.0.113.5".parse().expect("а"))
        );
    }

    #[test]
    fn the_slots_are_read_in_order() {
        let mut message = Message::new(libc::RTM_GET as u8, 0);
        message.address(libc::RTA_DST, &sockaddr("198.51.100.7".parse().expect("а")));
        message.address(
            libc::RTA_GATEWAY,
            &sockaddr("192.168.0.1".parse().expect("а")),
        );
        let bytes = message.finish(1);

        let found = addresses(&bytes);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0, libc::RTA_DST);
        assert_eq!(
            to_address(found[1].1),
            Some("192.168.0.1".parse().expect("а"))
        );
    }

    #[test]
    fn a_truncated_reply_does_not_panic() {
        // Ответ ядра — чужие данные: обрыв в середине здесь обычное дело.
        let mut message = Message::new(libc::RTM_GET as u8, 0);
        message.address(libc::RTA_DST, &sockaddr("198.51.100.7".parse().expect("а")));
        let mut bytes = message.finish(1);
        bytes.truncate(std::mem::size_of::<libc::rt_msghdr>() + 3);

        assert!(addresses(&bytes).is_empty());
    }
}
