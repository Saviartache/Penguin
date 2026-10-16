//! Куда пишет журнал: терминал — в stderr (stdout занят результатом, `--json`), окно — в `gui.log`.
//! Службу журнал заводит сам.

use std::sync::Mutex;

use penguin_config::logs::DailyLog;
use tracing_subscriber::EnvFilter;

use crate::args::Cli;

/// Начало имени файла журнала окна.
const GUI_PREFIX: &str = "gui.log";

/// Настраивает журнал под роль запуска.
pub fn init(cli: &Cli) {
    if cli.service {
        return;
    }
    let filter = filter(cli.verbose);
    if cli.writes_to_console() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_target(false)
            .try_init();
    } else if let Some(log) = open_gui_log() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_ansi(false)
            .with_writer(Mutex::new(log))
            .try_init();
    }
}

/// Журнал окна — в профиле пользователя: общий каталог принадлежит `root`.
fn open_gui_log() -> Option<DailyLog> {
    let directory = penguin_config::Paths::user().ok()?.data_dir().to_path_buf();
    std::fs::create_dir_all(&directory).ok()?;
    DailyLog::open(&directory, GUI_PREFIX).ok()
}

/// `RUST_LOG` сильнее флага.
fn filter(verbose: bool) -> EnvFilter {
    let default = if verbose { "debug" } else { "info" };
    EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("penguin={default},warn")))
}

#[cfg(test)]
mod tests {
    use penguin_cli::args::Parsed;

    use super::*;
    use crate::args;

    fn cli(argv: &[&str]) -> Cli {
        match args::parse(argv.iter().map(|arg| (*arg).to_owned()).collect()) {
            Ok(Parsed::Run(cli)) => cli,
            other => panic!("не запуск: {other:?}"),
        }
    }

    #[test]
    fn the_verbose_flag_changes_the_level() {
        assert!(filter(false).to_string().contains("info"));
        assert!(filter(true).to_string().contains("debug"));
    }

    #[test]
    fn terminal_roles_write_to_the_error_stream() {
        // В stdout идёт результат команды: смешать их значит сломать `--json`.
        assert!(cli(&["doctor"]).writes_to_console());
        assert!(cli(&["service", "status"]).writes_to_console());
        assert!(cli(&["--foreground"]).writes_to_console());
    }

    #[test]
    fn the_window_does_not_write_to_a_terminal_it_does_not_have() {
        assert!(!cli(&[]).writes_to_console());
    }

    #[test]
    fn the_window_and_the_service_keep_separate_files() {
        assert_ne!(GUI_PREFIX, "penguin.log");
    }
}
