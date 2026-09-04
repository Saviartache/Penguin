//! `/dev/net/tun`.
//!
//! Адаптер создаётся одним `ioctl` над устройством ядра и живёт ровно столько,
//! сколько открыт дескриптор: закрылся клиент — исчез и интерфейс. Отдельного
//! отката, в отличие от маршрутов, здесь не нужно.

mod netif;

use std::os::fd::OwnedFd;

use crate::config::TunConfig;
use crate::error::{TunError, TunResult};
use crate::platform::unix::{Header, UnixTun};

/// Устройство ядра, через которое создаются адаптеры.
const DEVICE: &str = "/dev/net/tun";

/// Адаптер без канального заголовка. `IFF_TUN | IFF_NO_PI`.
///
/// `IFF_NO_PI` важен: без него ядро ставит перед каждым пакетом свои четыре
/// байта, и стек получал бы не то, что договорено
/// ([`crate::device::TunDevice`]).
const ADAPTER_FLAGS: i16 = 0x0001 | 0x1000;

/// Открывает адаптер и настраивает интерфейс.
pub async fn open(config: &TunConfig) -> TunResult<UnixTun> {
    let device = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(DEVICE)
        .map_err(|err| match err.kind() {
            // Устройства нет — значит, не загружен модуль ядра. Самая частая
            // причина на серверах и в контейнерах, и лечится она одной
            // командой, которую и надо назвать.
            std::io::ErrorKind::NotFound => TunError::TunModuleMissing,
            std::io::ErrorKind::PermissionDenied => TunError::PermissionDenied,
            _ => TunError::Io(err),
        })?;
    let fd = OwnedFd::from(device);

    // Имя запрашивается, но последнее слово за ядром: занятое имя оно заменит
    // своим, и настраивать дальше надо именно то, что оно вернуло.
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
        // `IFF_NO_PI` — четвёртый бит второго байта. Без него ядро ставит
        // перед каждым пакетом свои четыре байта, и стек читает мусор вместо
        // заголовка IP.
        const IFF_TUN: i16 = 0x0001;
        const IFF_NO_PI: i16 = 0x1000;
        assert_eq!(ADAPTER_FLAGS & IFF_TUN, IFF_TUN);
        assert_eq!(ADAPTER_FLAGS & IFF_NO_PI, IFF_NO_PI);
    }

    #[tokio::test]
    async fn opening_without_privileges_fails_clearly() {
        // Тест идёт от обычного пользователя: адаптер не создастся. Проверяем
        // не это, а то, что ошибка называет причину и не паникует.
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
