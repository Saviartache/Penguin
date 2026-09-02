//! `/dev/net/tun`.
//!
//! Пока не реализовано: клиент собирается и работает под Linux в режиме
//! прокси (`penguin-inbound`), а тоннель требует своей работы с netlink и
//! правами.
//!
//! Заглушка возвращает внятную ошибку, а не притворяется рабочей: молчаливый
//! отказ поднять тоннель — худший исход из возможных.

use crate::config::TunConfig;
use crate::error::{TunError, TunResult};

/// Адаптер Linux.
#[derive(Debug)]
pub struct LinuxTun;

impl LinuxTun {
    /// Открывает адаптер.
    pub async fn open(_config: &TunConfig) -> TunResult<Self> {
        Err(TunError::Unsupported)
    }
}
