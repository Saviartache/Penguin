//! Виртуальный сетевой интерфейс: чтение и запись IP-пакетов.
//!
//! Отдаёт клиенту пакеты машины и принимает ответные; разбор — в
//! `penguin-netstack`, маршруты — в `penguin-platform`. Требует прав
//! администратора и драйвера (Wintun), взамен ловит трафик приложений без
//! настроек прокси.

pub mod config;
pub mod device;
pub mod error;
pub mod packet;
pub mod platform;

pub use config::TunConfig;
pub use device::{TunDevice, driver_available, open};
pub use error::{TunError, TunResult};
