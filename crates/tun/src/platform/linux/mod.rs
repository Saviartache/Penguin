//! `/dev/net/tun`: интерфейс живёт, пока открыт дескриптор.

mod netif;

use std::os::fd::OwnedFd;

use crate::config::TunConfig;
use crate::error::{TunError, TunResult};
use crate::platform::unix::{Header, UnixTun};

/// Устройство ядра, через которое создаются адаптеры.
const DEVICE: &str = "/dev/net/tun";

/// `IFF_TUN | IFF_NO_PI`: без `IFF_NO_PI` ядро добавляет перед пакетом 4 байта.
const ADAPTER_FLAGS: i16 = 0x0001 | 0x1000;

/// Открывает адаптер и настраивает интерфейс.
pub async fn open(config: &TunConfig) -> TunResult<UnixTun> {
    let device = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(DEVICE)
        .map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => TunError::TunModuleMissing,
            std::io::ErrorKind::PermissionDenied => TunError::PermissionDenied,
            _ => TunError::Io(err),
        })?;
    let fd = OwnedFd::from(device);

    // Ядро может заменить занятое имя; настраиваем то, что оно вернуло.
    let mut request = netif::IfReq::new(&config.name)?.with_flags(ADAPTER_FLAGS);
    netif::ioctl(&fd, netif::request::TUNSETIFF, &mut request)?;
    let name = request.name();

    netif::configure(&name, config.ipv4.0, config.ipv4_netmask(), config.mtu)?;

    tracing::info!(name, mtu = config.mtu, "адаптер создан");
    UnixTun::new(fd, name, config.mtu, Header::None).map_err(TunError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_adapter_carries_no_link_header() {
        const IFF_TUN: i16 = 0x0001;
        const IFF_NO_PI: i16 = 0x1000;
        assert_eq!(ADAPTER_FLAGS & IFF_TUN, IFF_TUN);
        assert_eq!(ADAPTER_FLAGS & IFF_NO_PI, IFF_NO_PI);
    }

    #[tokio::test]
    async fn opening_without_privileges_fails_clearly() {
        let config = TunConfig {
            name: "penguintest".to_owned(),
            ..TunConfig::default()
        };
        match open(&config).await {
            Ok(device) => {
                use crate::device::TunDevice;
                device.close().await.expect("закрывается");
            }
            Err(err) => assert!(
                err.needs_user_action() || matches!(err, TunError::Io(_)),
                "неожиданная ошибка: {err}"
            ),
        }
    }
}
