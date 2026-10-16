//! Системные настройки DNS: подмена на время сеанса и обязательный возврат.
//!
//! Перехвата порта 53 из TUN мало: резолвер Windows обходит таблицу маршрутизации, поэтому
//! единственным DNS на сеанс объявляется адрес адаптера. Оставленный адрес ведёт в несуществующий
//! адаптер, и сайты перестают открываться.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

use std::net::IpAddr;

use crate::error::PlatformResult;

/// Подменённые настройки DNS с гарантированным возвратом.
#[derive(Debug, Default)]
pub struct DnsOverride {
    /// Интерфейсы, у которых настройки подменены.
    touched: Vec<u32>,
}

impl DnsOverride {
    /// Ничего не подменено.
    pub fn new() -> Self {
        Self::default()
    }

    /// Объявляет указанный адрес единственным DNS интерфейса.
    pub fn apply(&mut self, interface_index: u32, server: IpAddr) -> PlatformResult<()> {
        set_dns(interface_index, server)?;
        tracing::info!(interface_index, %server, "DNS интерфейса подменён");
        self.touched.push(interface_index);
        Ok(())
    }

    /// Возвращает настройки, какими они были; ошибка одного интерфейса не останавливает остальные.
    pub fn restore(&mut self) -> PlatformResult<()> {
        let touched = std::mem::take(&mut self.touched);
        let mut first_error = None;

        for index in touched {
            if let Err(err) = reset_dns(index) {
                tracing::error!(index, %err, "настройки DNS не восстановлены");
                first_error.get_or_insert(err);
            }
        }

        first_error.map_or(Ok(()), Err)
    }

    /// Что-то подменено.
    pub fn is_active(&self) -> bool {
        !self.touched.is_empty()
    }
}

impl Drop for DnsOverride {
    fn drop(&mut self) {
        if self.is_active()
            && let Err(err) = self.restore()
        {
            tracing::error!(%err, "настройки DNS остались подменёнными");
        }
    }
}

/// Возвращает настройки, подменённые прошлым запуском: список подмены жил в памяти, прежние
/// значения лежат в файле.
pub fn recover_leftovers() -> PlatformResult<()> {
    #[cfg(windows)]
    {
        // DNS подменяется у адаптера тоннеля и исчезает вместе с ним.
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        // Номер не нужен: возвращается сохранённая копия `resolv.conf`.
        linux::reset(0)
    }
    #[cfg(target_os = "macos")]
    {
        macos::reset()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Ok(())
    }
}

fn set_dns(interface_index: u32, server: IpAddr) -> PlatformResult<()> {
    #[cfg(windows)]
    {
        windows::set(interface_index, server)
    }
    #[cfg(target_os = "linux")]
    {
        linux::set(interface_index, server)
    }
    #[cfg(target_os = "macos")]
    {
        // utun сетевой службой не считается: подменяются настройки всей машины.
        let _ = interface_index;
        macos::set(server)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (interface_index, server);
        Err(crate::error::PlatformError::Unsupported("настройки DNS"))
    }
}

fn reset_dns(interface_index: u32) -> PlatformResult<()> {
    #[cfg(windows)]
    {
        windows::reset(interface_index)
    }
    #[cfg(target_os = "linux")]
    {
        linux::reset(interface_index)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = interface_index;
        macos::reset()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = interface_index;
        Err(crate::error::PlatformError::Unsupported("настройки DNS"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_inactive() {
        assert!(!DnsOverride::new().is_active());
    }

    #[test]
    fn restoring_nothing_is_fine() {
        let mut settings = DnsOverride::new();
        settings.restore().expect("восстанавливать нечего");
    }
}
