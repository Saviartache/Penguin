//! Интеграция со службой операционной системы.
//!
//! Главный поток вызывает диспетчер; остальное общее с обычным запуском
//! ([`crate::runtime`]).

#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

use std::path::PathBuf;

use anyhow::Result;

/// Запускает демона как службу операционной системы.
pub fn run_as_service(config_dir: Option<PathBuf>) -> Result<()> {
    #[cfg(windows)]
    {
        windows::run(config_dir)
    }
    #[cfg(not(windows))]
    {
        unix::run(config_dir)
    }
}
