//! `TunDevice` — трейт устройства; платформа выше по стеку не видна.

use async_trait::async_trait;
use bytes::BytesMut;

use crate::config::TunConfig;
use crate::error::TunResult;

/// Виртуальный сетевой интерфейс: отдаёт и принимает IP-пакеты целиком, без канального заголовка.
#[async_trait]
pub trait TunDevice: Send + Sync + 'static {
    /// Имя адаптера в системе.
    fn name(&self) -> &str;

    /// Наибольший размер пакета.
    fn mtu(&self) -> u16;

    /// Индекс интерфейса — по нему платформа ставит маршруты.
    fn index(&self) -> Option<u32> {
        None
    }

    /// Ждёт следующий пакет от системы.
    async fn recv(&self) -> TunResult<BytesMut>;

    /// Забирает уже пришедший пакет, не ожидая; `None` — пока пусто.
    fn try_recv(&self) -> Option<BytesMut> {
        None
    }

    /// Отправляет пакет системе.
    async fn send(&self, packet: &[u8]) -> TunResult<()>;

    /// Закрывает адаптер; после этого [`Self::recv`] возвращает [`crate::error::TunError::Closed`].
    async fn close(&self) -> TunResult<()>;
}

/// Открывает устройство для текущей платформы.
pub async fn open(config: &TunConfig) -> TunResult<Box<dyn TunDevice>> {
    #[cfg(windows)]
    {
        Ok(Box::new(
            crate::platform::windows::WintunDevice::open(config).await?,
        ))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(crate::platform::linux::open(config).await?))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(crate::platform::macos::open(config).await?))
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = config;
        Err(crate::error::TunError::Unsupported)
    }
}

/// Есть ли драйвер, без которого тоннель не поднимется (права не проверяются).
pub fn driver_available() -> TunResult<()> {
    #[cfg(windows)]
    {
        crate::platform::windows::load_driver().map(|_| ())
    }
    #[cfg(target_os = "linux")]
    {
        if std::path::Path::new("/dev/net/tun").exists() {
            Ok(())
        } else {
            Err(crate::error::TunError::TunModuleMissing)
        }
    }
    #[cfg(target_os = "macos")]
    {
        Ok(())
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Err(crate::error::TunError::Unsupported)
    }
}
