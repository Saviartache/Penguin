//! Настройка utun через `ioctl` (не через `ifconfig`): адрес, «тот конец», MTU.

use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd};

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};

use crate::error::{TunError, TunResult};

/// Длина имени интерфейса вместе с завершающим нулём.
const NAME_LEN: usize = 16;

/// Добавить адрес интерфейсу. `_IOW('i', 26, struct ifaliasreq)`.
const SIOCAIFADDR: libc::c_ulong = 0x8040_691A;
/// Задать MTU. `_IOW('i', 52, struct ifreq)`.
const SIOCSIFMTU: libc::c_ulong = 0x8020_6934;

/// `struct in_aliasreq`; utun двухточечный, адрес назначения обязателен.
#[repr(C)]
struct AliasRequest {
    name: [u8; NAME_LEN],
    address: libc::sockaddr_in,
    destination: libc::sockaddr_in,
    netmask: libc::sockaddr_in,
}

/// Запрос к интерфейсу: имя и одно поле по смыслу команды.
#[repr(C)]
struct IfRequest {
    name: [u8; NAME_LEN],
    data: [u8; 16],
}

/// Адрес для ядра; в BSD длина `sin_len` обязательна.
fn sockaddr(address: Ipv4Addr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "размер sockaddr_in заведомо помещается в байт"
        )]
        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
        #[allow(
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            reason = "семейство адресов помещается в байт"
        )]
        sin_family: libc::AF_INET as u8,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.octets()),
        },
        sin_zero: [0; 8],
    }
}

/// Кладёт имя интерфейса в запрос.
fn name_bytes(name: &str) -> TunResult<[u8; NAME_LEN]> {
    let bytes = name.as_bytes();
    if bytes.len() >= NAME_LEN {
        return Err(TunError::adapter(
            name,
            format!("имя длиннее {} байт", NAME_LEN - 1),
        ));
    }
    let mut buffer = [0u8; NAME_LEN];
    buffer[..bytes.len()].copy_from_slice(bytes);
    Ok(buffer)
}

/// Задаёт адрес и MTU.
pub(super) fn configure(
    name: &str,
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: u16,
) -> TunResult<()> {
    let control = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )
    .map_err(|err| TunError::adapter(name, err))?;

    let mut alias = AliasRequest {
        name: name_bytes(name)?,
        address: sockaddr(address),
        destination: sockaddr(address),
        netmask: sockaddr(netmask),
    };
    ioctl(&control, SIOCAIFADDR, std::ptr::from_mut(&mut alias).cast())?;

    let mut request = IfRequest {
        name: name_bytes(name)?,
        data: [0; 16],
    };
    request.data[..4].copy_from_slice(&i32::from(mtu).to_ne_bytes());
    ioctl(
        &control,
        SIOCSIFMTU,
        std::ptr::from_mut(&mut request).cast(),
    )?;

    Ok(())
}

/// Выполняет `ioctl` и переводит отказ в ошибку с причиной.
fn ioctl(fd: &OwnedFd, request: libc::c_ulong, argument: *mut libc::c_void) -> TunResult<()> {
    #[allow(unsafe_code, reason = "настройка интерфейса через ioctl")]
    // SAFETY: `argument` указывает на структуру, размер которой зашит в `request`.
    let code = unsafe { libc::ioctl(fd.as_raw_fd(), request, argument) };

    if code < 0 {
        let err = std::io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::EPERM | libc::EACCES) => TunError::PermissionDenied,
            _ => TunError::Io(err),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_carries_its_own_length() {
        let address = sockaddr(Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(
            usize::from(address.sin_len),
            std::mem::size_of::<libc::sockaddr_in>()
        );
        assert_eq!(address.sin_addr.s_addr.to_ne_bytes(), [198, 18, 0, 1]);
    }

    #[test]
    fn the_alias_request_is_the_size_the_kernel_expects() {
        assert_eq!(std::mem::size_of::<AliasRequest>(), 64);
        assert_eq!((SIOCAIFADDR >> 16) & 0x1FFF, 64);
    }

    #[test]
    fn the_interface_request_is_the_size_the_kernel_expects() {
        assert_eq!(std::mem::size_of::<IfRequest>(), 32);
        assert_eq!((SIOCSIFMTU >> 16) & 0x1FFF, 32);
    }

    #[test]
    fn an_overlong_name_is_refused() {
        assert!(name_bytes("этоименослишкомдлинное").is_err());
        assert!(name_bytes("utun7").is_ok());
    }
}
