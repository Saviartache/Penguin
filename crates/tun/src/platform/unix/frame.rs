//! Кадрирование: Linux (`IFF_NO_PI`) отдаёт чистый пакет, macOS ставит перед ним семейство адресов.

use std::os::fd::{AsRawFd, BorrowedFd};

use bytes::{Buf, BytesMut};

/// Пакетов на одну аллокацию буфера чтения.
const BATCH: usize = 16;

/// Что стоит перед IP-пакетом в дескрипторе.
#[allow(dead_code, reason = "каждой системе нужен один вариант из двух")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Header {
    /// Ничего (Linux).
    None,
    /// Семейство адресов, 4 байта (macOS, utun).
    AddressFamily,
}

impl Header {
    const fn len(self) -> usize {
        match self {
            Self::None => 0,
            Self::AddressFamily => 4,
        }
    }
}

/// Читает один пакет в хвост `buffer` и снимает заголовок; аллокация раз в [`BATCH`] пакетов.
///
/// Конец файла — ошибка: пустой буфер крутил бы цикл чтения вечно. Короче заголовка — пустой буфер.
pub(super) fn read(
    fd: BorrowedFd<'_>,
    buffer: &mut BytesMut,
    mtu: u16,
    header: Header,
) -> std::io::Result<BytesMut> {
    let slot = usize::from(mtu) + header.len();
    if buffer.capacity() < slot {
        buffer.reserve(BATCH * slot);
    }
    let spare = buffer.spare_capacity_mut();

    #[allow(unsafe_code, reason = "чтение из дескриптора адаптера")]
    // SAFETY: запись идёт в выделенный неинициализированный хвост длиной не более `slot`.
    let read = unsafe {
        libc::read(
            fd.as_raw_fd(),
            spare.as_mut_ptr().cast::<libc::c_void>(),
            slot,
        )
    };
    let read = usize::try_from(read).map_err(|_| std::io::Error::last_os_error())?;
    if read == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
    }

    #[allow(unsafe_code, reason = "хвост инициализирован read()")]
    // SAFETY: `read` байт только что записаны ядром и не превышают ёмкость.
    unsafe {
        buffer.set_len(buffer.len() + read);
    }
    let mut packet = buffer.split();
    if read < header.len() {
        return Ok(BytesMut::new());
    }
    packet.advance(header.len());
    Ok(packet)
}

/// Пишет пакет, добавляя заголовок; `writev` вместо склейки в новый буфер.
pub(super) fn write(fd: BorrowedFd<'_>, packet: &[u8], header: Header) -> std::io::Result<()> {
    let family = address_family(packet).to_be_bytes();

    let pieces = [
        libc::iovec {
            iov_base: family.as_ptr().cast::<libc::c_void>().cast_mut(),
            iov_len: family.len(),
        },
        libc::iovec {
            iov_base: packet.as_ptr().cast::<libc::c_void>().cast_mut(),
            iov_len: packet.len(),
        },
    ];
    let (pieces, count) = match header {
        Header::None => (&pieces[1..], 1),
        Header::AddressFamily => (&pieces[..], 2),
    };

    #[allow(unsafe_code, reason = "запись в дескриптор адаптера")]
    // SAFETY: iovec указывают на живые срезы; ядро их только читает.
    let written = unsafe { libc::writev(fd.as_raw_fd(), pieces.as_ptr(), count) };
    if written < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Семейство адресов по версии IP; неверное система молча отбрасывает.
fn address_family(packet: &[u8]) -> u32 {
    let version = packet.first().map_or(0, |byte| byte >> 4);
    #[allow(clippy::cast_sign_loss, reason = "константа семейства адресов")]
    if version == 6 {
        libc::AF_INET6 as u32
    } else {
        libc::AF_INET as u32
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
    fn a_closed_adapter_is_an_error_not_an_empty_packet() {
        use std::os::fd::AsFd;

        let (reader, writer) = std::io::pipe().expect("труба заводится");
        drop(writer);

        let err = read(
            reader.as_fd(),
            &mut BytesMut::new(),
            1500,
            Header::AddressFamily,
        )
        .expect_err("конец файла — это ошибка");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn packets_share_one_buffer_and_lose_the_header() {
        use std::io::Write;
        use std::os::fd::AsFd;

        let (reader, mut writer) = std::io::pipe().expect("труба заводится");
        writer.write_all(&[0, 0, 0, 2, 0x45, 1]).expect("запись");
        let mut buffer = BytesMut::new();
        let packet =
            read(reader.as_fd(), &mut buffer, 1500, Header::AddressFamily).expect("пакет читается");
        assert_eq!(&packet[..], &[0x45, 1]);
    }

    #[test]
    fn the_family_comes_from_the_version_nibble() {
        assert_eq!(address_family(&[0x45, 0, 0, 20]), libc::AF_INET as u32);
        assert_eq!(address_family(&[0x60, 0, 0, 0]), libc::AF_INET6 as u32);
    }

    #[test]
    fn an_empty_packet_is_not_ipv6() {
        assert_eq!(address_family(&[]), libc::AF_INET as u32);
    }
}
