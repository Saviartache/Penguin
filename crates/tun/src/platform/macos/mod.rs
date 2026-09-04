//! utun через `PF_SYSTEM`.
//!
//! Своего устройства вроде `/dev/net/tun` в macOS нет: адаптер создаётся
//! подключением к управляющему сокету ядра `com.apple.net.utun_control`.
//! Дальше он ведёт себя как обычный дескриптор — с одной оговоркой: перед
//! каждым пакетом стоит семейство адресов ([`super::unix`]).
//!
//! Имя адаптера выбирает система: `utun0`, `utun1` и так далее. Имя из
//! настроек здесь не действует, и это не недосмотр — интерфейсы utun система
//! нумерует сама.

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
        // Не предупреждение: имя utun выбирает система, и настройка на него
        // повлиять не может. Сказать об этом всё же надо — иначе человек
        // будет искать в `ifconfig` имя, которое сам же и вписал.
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
    let raw = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if raw < 0 {
        return Err(classify(std::io::Error::last_os_error()));
    }
    #[allow(unsafe_code, reason = "владение только что созданным дескриптором")]
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // Номер управляющего сокета не фиксирован: его выдаёт ядро по имени.
    let id = control_id(&fd)?;

    let address = libc::sockaddr_ctl {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "размер sockaddr_ctl заведомо помещается в байт"
        )]
        sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
        #[allow(
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            reason = "семейство адресов помещается в байт"
        )]
        sc_family: libc::AF_SYSTEM as u8,
        #[allow(
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            reason = "константа подсистемы помещается в u16"
        )]
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: id,
        // Ноль означает «любой свободный»: занимать конкретный номер незачем,
        // а занятый ядро всё равно не отдаст.
        sc_unit: 0,
        sc_reserved: [0; 5],
    };

    #[allow(unsafe_code, reason = "подключение к управляющему сокету ядра")]
    let code = unsafe {
        libc::connect(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            std::ptr::from_ref(&address).cast::<libc::sockaddr>(),
            #[allow(
                clippy::cast_possible_truncation,
                reason = "размер sockaddr_ctl заведомо помещается в socklen_t"
            )]
            {
                std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t
            },
        )
    };
    if code < 0 {
        return Err(classify(std::io::Error::last_os_error()));
    }

    Ok(fd)
}

/// Спрашивает у ядра номер управляющего сокета по его имени.
fn control_id(fd: &OwnedFd) -> TunResult<u32> {
    let mut info = libc::ctl_info {
        ctl_id: 0,
        ctl_name: [0; 96],
    };
    for (slot, byte) in info.ctl_name.iter_mut().zip(CONTROL_NAME) {
        #[allow(clippy::cast_possible_wrap, reason = "имя состоит из символов ASCII")]
        {
            *slot = *byte as libc::c_char;
        }
    }

    #[allow(unsafe_code, reason = "запрос номера управляющего сокета")]
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
    #[allow(
        clippy::cast_possible_truncation,
        reason = "размер буфера имени заведомо помещается в socklen_t"
    )]
    let mut length = buffer.len() as libc::socklen_t;

    #[allow(unsafe_code, reason = "чтение имени адаптера у ядра")]
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

/// Переводит отказ системы в ошибку с причиной.
///
/// Создание utun требует прав администратора, и это самая частая причина
/// отказа. Пользователь должен прочитать про права, а не «Operation not
/// permitted».
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
        // Опечатка здесь означает `ENOENT` от ядра и адаптер, который «не
        // создаётся» без единого намёка на причину.
        assert_eq!(CONTROL_NAME, b"com.apple.net.utun_control");
        assert!(CONTROL_NAME.len() < 96, "имя не помещается в `ctl_info`");
    }

    #[tokio::test]
    async fn opening_without_privileges_fails_clearly() {
        // Тест идёт от обычного пользователя: адаптер не создастся. Проверяем
        // не это, а то, что ошибка называет причину и не паникует.
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
