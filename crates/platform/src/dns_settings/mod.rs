//! Системные настройки DNS: подмена на время сеанса и возврат назад.
//!
//! Перехвата порта 53 из TUN хватает не всегда. Часть системных служб — и,
//! что важнее, сам резолвер Windows — умеет обходить таблицу маршрутизации и
//! спрашивать «свои» серверы напрямую по другим интерфейсам. Лечится это
//! только тем, чтобы на время сеанса объявить единственным DNS адрес нашего
//! адаптера.
//!
//! Отсюда обязанность вернуть всё назад. Оставленный адрес указывает на
//! адаптер, которого больше нет, и у пользователя перестают открываться сайты
//! — при выключенном VPN, который он даже не заподозрит.

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

    /// Возвращает настройки, какими они были.
    ///
    /// Продолжает после ошибки: не восстановив первый интерфейс, нельзя
    /// бросать второй.
    pub fn restore(&mut self) -> PlatformResult<()> {
        let touched = std::mem::take(&mut self.touched);
        let mut first_error = None;

        for index in touched {
            if let Err(err) = reset_dns(index) {
                tracing::error!(index, %err, "настройки DNS не восстановлены");
                first_error.get_or_insert(err);
            }
        }

        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Что-то подменено.
    pub fn is_active(&self) -> bool {
        !self.touched.is_empty()
    }
}

impl Drop for DnsOverride {
    fn drop(&mut self) {
        // Оставленный адрес указывает на несуществующий адаптер: у
        // пользователя перестают открываться сайты, и связать это с уже
        // закрытым клиентом он не сможет.
        if self.is_active()
            && let Err(err) = self.restore()
        {
            tracing::error!(%err, "настройки DNS остались подменёнными");
        }
    }
}

/// Возвращает настройки, подменённые прошлым запуском.
///
/// [`DnsOverride::restore`] здесь не поможет: она возвращает то, что подменила
/// сама, а список подменённого живёт в памяти процесса, которого больше нет.
/// Прежние значения при этом сохранены в файле — ровно на этот случай, — и
/// вернуть их можно только отсюда.
pub fn recover_leftovers() -> PlatformResult<()> {
    #[cfg(windows)]
    {
        // Нечего возвращать: на Windows DNS подменяется у самого адаптера
        // тоннеля, и вместе с адаптером подмена исчезает. Пережить процесс она
        // не может.
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        // Номер интерфейса не нужен: возвращается `resolv.conf` целиком,
        // из сохранённой копии.
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
        // Номер интерфейса здесь не при чём: сетевой службой utun не
        // считается, и подменять приходится настройки всей машины.
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
        // Восстановление вызывается на каждом пути выхода.
        let mut settings = DnsOverride::new();
        settings.restore().expect("восстанавливать нечего");
    }
}
