//! utun через `PF_SYSTEM`: адаптер создаётся подключением к `com.apple.net.utun_control`.
//!
//! Имя (`utunN`) выбирает система; перед каждым пакетом стоит семейство адресов.

mod netif;

use std::os::fd::{FromRawFd, OwnedFd};

use crate::config::TunConfig;
use crate::error::{TunError, TunResult};
use crate::platform::unix::{Header, UnixTun};

/// Имя управляющего сокета ядра.
const CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";

/// Открывает адаптер и настраивает интерфейс.
pub async fn open(config: &TunConfig) -> TunResult<UnixTun> {
    let fd = connect_to_control()?;
    let name = interface_name(&fd)?;

    netif::configure(&name, config.ipv4.0, config.ipv4_netmask(), config.mtu)?;

    if name != config.name {
        tracing::debug!(
            requested = config.name,
            actual = name,
            "имя адаптера назначено системой"
        );
    }
    tracing::info!(name, mtu = config.mtu, "адаптер создан");

    UnixTun::new(fd, name, config.mtu, Header::AddressFamily).map_err(TunError::Io)
}

/// Подключается к управляющему сокету и получает свежий utun.
fn connect_to_control() -> TunResult<OwnedFd> {
    #[allow(unsafe_code, reason = "создание управляющего сокета ядра")]
    // SAFETY: вызов без указателей.
    let raw = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if raw < 0 {
        return Err(classify(std::io::Error::last_os_error()));
    }
    #[allow(unsafe_code, reason = "владение только что созданным дескриптором")]
    // SAFETY: `raw` только что создан и никем не владеется.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let id = control_id(&fd)?;

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "константы адресации помещаются в поля"
    )]
    let address = libc::sockaddr_ctl {
        sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
        sc_family: libc::AF_SYSTEM as u8,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: id,
        // 0 — любой свободный номер.
        sc_unit: 0,
        sc_reserved: [0; 5],
    };

    #[allow(unsafe_code, reason = "подключение к управляющему сокету ядра")]
    #[allow(clippy::cast_possible_truncation, reason = "размер структуры мал")]
    // SAFETY: `address` живёт до конца вызова, длина совпадает с типом.
    let code = unsafe {
        libc::connect(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            std::ptr::from_ref(&address).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    };
    if code < 0 {
        return Err(classify(std::io::Error::last_os_error()));
    }

    Ok(fd)
}

/// Спрашивает у ядра номер управляющего сокета по имени.
fn control_id(fd: &OwnedFd) -> TunResult<u32> {
    let mut info = libc::ctl_info {
        ctl_id: 0,
        ctl_name: [0; 96],
    };
    for (slot, byte) in info.ctl_name.iter_mut().zip(CONTROL_NAME) {
        #[allow(clippy::cast_possible_wrap, reason = "ASCII")]
        {
            *slot = *byte as libc::c_char;
        }
    }

    #[allow(unsafe_code, reason = "запрос номера управляющего сокета")]
    // SAFETY: `info` — изменяемая структура нужного типа.
    let code = unsafe {
        libc::ioctl(
            std::os::fd::AsRawFd::as_raw_fd(fd),
            libc::CTLIOCGINFO,
            std::ptr::from_mut(&mut info),
        )
    };
    if code < 0 {
        return Err(classify(std::io::Error::last_os_error()));
    }
    Ok(info.ctl_id)
}

/// Имя, которое система дала адаптеру.
fn interface_name(fd: &OwnedFd) -> TunResult<String> {
    let mut buffer = [0u8; 32];
    #[allow(clippy::cast_possible_truncation, reason = "32 помещается в socklen_t")]
    let mut length = buffer.len() as libc::socklen_t;

    #[allow(unsafe_code, reason = "чтение имени адаптера у ядра")]
    // SAFETY: буфер и длина согласованы.
    let code = unsafe {
        libc::getsockopt(
            std::os::fd::AsRawFd::as_raw_fd(fd),
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            &mut length,
        )
    };
    if code < 0 {
        return Err(classify(std::io::Error::last_os_error()));
    }

    let end = buffer.iter().position(|byte| *byte == 0).unwrap_or(0);
    Ok(String::from_utf8_lossy(&buffer[..end]).into_owned())
}

/// `EPERM`/`EACCES` — нужны права администратора.
fn classify(err: std::io::Error) -> TunError {
    match err.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => TunError::PermissionDenied,
        _ => TunError::Io(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_errors_tell_the_user_what_to_do() {
        let err = classify(std::io::Error::from_raw_os_error(libc::EPERM));
        assert!(matches!(err, TunError::PermissionDenied));
        assert!(err.needs_user_action());
    }

    #[test]
    fn the_control_name_is_the_one_the_kernel_knows() {
        assert_eq!(CONTROL_NAME, b"com.apple.net.utun_control");
        assert!(CONTROL_NAME.len() < 96, "имя не помещается в `ctl_info`");
    }

    #[tokio::test]
    async fn opening_without_privileges_fails_clearly() {
        match open(&TunConfig::default()).await {
            Ok(device) => {
                use crate::device::TunDevice;
                assert!(device.name().starts_with("utun"));
                device.close().await.expect("закрывается");
            }
            Err(err) => assert!(
                err.needs_user_action() || matches!(err, TunError::Io(_)),
                "неожиданная ошибка: {err}"
            ),
        }
    }
}
