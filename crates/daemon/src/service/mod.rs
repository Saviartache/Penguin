//! Интеграция со службой операционной системы.
//!
//! Способ запуска у службы свой: она не владеет своим главным потоком —
//! его вызывает диспетчер, — и обязана отвечать ему на команды. Всё
//! остальное, включая порядок подъёма и остановки, общее с обычным запуском
//! и живёт в [`crate::runtime`].

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
