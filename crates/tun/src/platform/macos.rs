//! utun через `PF_SYSTEM`.
//!
//! Пока не реализовано — см. [`super::linux`]: причина и подход те же.

use crate::config::TunConfig;
use crate::error::{TunError, TunResult};

/// Адаптер macOS.
#[derive(Debug)]
pub struct MacosTun;

impl MacosTun {
    /// Открывает адаптер.
    pub async fn open(_config: &TunConfig) -> TunResult<Self> {
        Err(TunError::Unsupported)
    }
}
