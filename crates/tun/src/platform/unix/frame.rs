//! Кадрирование пакета на пути через дескриптор.
//!
//! Договор устройства — **чистый IP-пакет** ([`crate::device::TunDevice`]), а
//! системы этот договор нарушают по-разному: Linux с `IFF_NO_PI` не добавляет
//! ничего, macOS ставит перед каждым пакетом семейство адресов четырьмя
//! байтами. Разница живёт здесь и наружу не выходит.

use std::os::fd::{AsRawFd, BorrowedFd};

use bytes::BytesMut;

/// Что стоит перед IP-пакетом в дескрипторе.
///
/// Каждая система пользуется ровно одним вариантом, поэтому второй в её
/// сборке никем не создаётся. Это не мёртвый код: перечисление и заведено
/// затем, чтобы разница была видна одним взглядом, а не пряталась по `cfg`.
#[allow(dead_code, reason = "каждой системе нужен один вариант из двух")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Header {
    /// Ничего: пакет лежит как есть (Linux, `IFF_NO_PI`).
    None,
    /// Семейство адресов четырьмя байтами (macOS, utun).
    AddressFamily,
}

impl Header {
    /// Сколько байт занимает.
    const fn len(self) -> usize {
        match self {
            Self::None => 0,
            Self::AddressFamily => 4,
        }
    }
}

/// Читает один пакет, снимая заголовок.
///
/// `Ok(None)` — пришло меньше, чем один заголовок: пакета в этом нет, и
/// отдавать наверх нечего.
pub(super) fn read(fd: BorrowedFd<'_>, mtu: u16, header: Header) -> std::io::Result<BytesMut> {
    let mut buffer = BytesMut::zeroed(usize::from(mtu) + header.len());

    #[allow(unsafe_code, reason = "чтение из дескриптора адаптера")]
    let read = unsafe {
        libc::read(
            fd.as_raw_fd(),
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
        )
    };
    if read < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let read = usize::try_from(read).unwrap_or(0);
    if read < header.len() {
        // Заголовок без пакета. Не ошибка ввода-вывода, но и не пакет:
        // пустой буфер стек отбросит сам.
        return Ok(BytesMut::new());
    }

    buffer.truncate(read);
    let _ = buffer.split_to(header.len());
    Ok(buffer)
}

/// Пишет один пакет, добавляя заголовок.
///
/// Двумя кусками через `writev`, а не склейкой в новый буфер: склейка
/// означала бы копию каждого исходящего пакета ради четырёх байт впереди.
pub(super) fn write(fd: BorrowedFd<'_>, packet: &[u8], header: Header) -> std::io::Result<()> {
    let family = address_family(packet).to_be_bytes();

    let mut pieces = [
        libc::iovec {
            iov_base: family.as_ptr().cast::<libc::c_void>().cast_mut(),
            iov_len: family.len(),
        },
        libc::iovec {
            iov_base: packet.as_ptr().cast::<libc::c_void>().cast_mut(),
            iov_len: packet.len(),
        },
    ];
    // Без заголовка пишется только сам пакет — второй кусок становится
    // первым и единственным.
    let (pieces, count) = match header {
        Header::None => (&mut pieces[1..], 1),
        Header::AddressFamily => (&mut pieces[..], 2),
    };

    #[allow(unsafe_code, reason = "запись в дескриптор адаптера")]
    let written = unsafe { libc::writev(fd.as_raw_fd(), pieces.as_ptr(), count) };
    if written < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Семейство адресов пакета — по версии в первом полубайте.
///
/// Свободная функция с тестом: перепутанное семейство означает пакет, который
/// система молча отбрасывает, и тоннель без единой ошибки в журнале.
fn address_family(packet: &[u8]) -> u32 {
    const IPV6: u8 = 6;

    let version = packet.first().map_or(0, |byte| byte >> 4);
    if version == IPV6 {
        #[allow(clippy::cast_sign_loss, reason = "константа семейства адресов")]
        {
            libc::AF_INET6 as u32
        }
    } else {
        #[allow(clippy::cast_sign_loss, reason = "константа семейства адресов")]
        {
            libc::AF_INET as u32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_length_matches_the_platform() {
        assert_eq!(Header::None.len(), 0);
        assert_eq!(Header::AddressFamily.len(), 4);
    }

    #[test]
    fn the_family_comes_from_the_version_nibble() {
        // Первый полубайт — версия IP; всё остальное в пакете к выбору
        // семейства отношения не имеет.
        assert_eq!(address_family(&[0x45, 0, 0, 20]), libc::AF_INET as u32);
        assert_eq!(address_family(&[0x60, 0, 0, 0]), libc::AF_INET6 as u32);
    }

    #[test]
    fn an_empty_packet_is_not_ipv6() {
        // Пустой буфер приходит от закрытого адаптера; принять его за IPv6
        // означало бы отправить системе заведомо неверный кадр.
        assert_eq!(address_family(&[]), libc::AF_INET as u32);
    }
}
