//! Демонизация и сигналы.
//!
//! Остаётся на переднем плане: запуском управляют systemd и launchd.
//!
//! # Куда пишется журнал
//!
//! В файл, а не в стандартный поток: launchd без `StandardErrorPath` его
//! теряет. Файл общий для всех систем.

use std::path::PathBuf;

use anyhow::{Context, Result};
use penguin_config::Paths;

/// Запускает демона под управлением systemd или launchd.
pub fn run(config_dir: Option<PathBuf>) -> Result<()> {
    // Журнал раньше всего, чтобы ловить ошибки сборки
    let paths = service_paths(config_dir)?;
    crate::logging::init_file(paths.data_dir(), false);

    let result = crate::runtime::run_blocking_paths(Some(paths));
    if let Err(err) = &result {
        tracing::error!(error = %format_args!("{err:#}"), "system service failed");
    }
    result
}

fn service_paths(config_dir: Option<PathBuf>) -> Result<Paths> {
    let machine = Paths::machine().context("machine configuration paths are unavailable")?;
    if let Some(dir) = config_dir
        && dir != machine.config_dir()
    {
        return Ok(Paths::rooted(dir));
    }
    Ok(machine)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_paths_do_not_depend_on_directory_existence_or_home() {
        for directory in [None, Some(PathBuf::from("/etc/penguin"))] {
            let paths = service_paths(directory).expect("machine paths");
            assert_eq!(paths.config_dir(), std::path::Path::new("/etc/penguin"));
            assert_eq!(paths.data_dir(), std::path::Path::new("/var/lib/penguin"));
        }
    }
}
