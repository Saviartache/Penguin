//! Демонизация и сигналы.
//!
//! Демонизировать себя не нужно и вредно: служба должна оставаться на переднем
//! плане, а поднимать и останавливать её — дело systemd и launchd. От нас
//! требуется разобрать `SIGTERM` (это делает [`crate::runtime`]) и не потерять
//! журнал.
//!
//! # Куда пишется журнал
//!
//! В файл, а не в стандартный поток. У systemd поток ещё подхватывает journald,
//! а launchd без `StandardErrorPath` выбрасывает его целиком — и служба,
//! которая не поднялась, не оставляет после себя ни строчки. Файл один и тот
//! же на всех системах (на Windows его открывает [`super::windows`]), и искать
//! его человеку приходится в одном месте.

use std::path::PathBuf;

use anyhow::{Context, Result};
use penguin_config::Paths;

/// Запускает демона под управлением systemd или launchd.
pub fn run(config_dir: Option<PathBuf>) -> Result<()> {
    // Журнал до всего остального: ошибка сборки настроек — как раз то, ради
    // чего его и заводят.
    let paths = service_paths(config_dir)?;
    let _guard = crate::logging::init_file(paths.data_dir(), false);

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
