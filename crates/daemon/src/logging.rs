//! Журнал службы: в файл с суточной ротацией (у службы нет терминала) или в терминал.

use std::path::Path;
use std::sync::{Mutex, OnceLock};

use penguin_config::logs::DailyLog;
use penguin_config::schema::app::LogLevel;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

/// Начало имени файла журнала; у окна своё, чтобы уборка одного не задевала другой.
const PREFIX: &str = "penguin.log";

/// Смена уровня уже заведённого журнала: он создаётся раньше, чем читаются настройки.
static RELOAD: OnceLock<Box<dyn Fn(EnvFilter) + Send + Sync>> = OnceLock::new();

/// Настраивает журнал в терминал.
pub fn init_console(verbose: bool) {
    install(std::io::stdout, true, verbose);
}

/// Настраивает журнал в файл; без файла служба работает, но без журнала.
pub fn init_file(directory: &Path, verbose: bool) {
    if let Some(log) = open_log(directory) {
        install(Mutex::new(log), false, verbose);
    }
}

/// Меняет уровень журнала на работающей службе, если он не задан руками.
pub fn set_level(level: LogLevel) {
    if let Some(reload) = RELOAD.get() {
        reload(level_filter(level.as_str()));
    }
}

fn open_log(directory: &Path) -> Option<DailyLog> {
    if let Err(err) = std::fs::create_dir_all(directory) {
        eprintln!("не удалось создать каталог журнала: {err}");
        return None;
    }
    match DailyLog::open(directory, PREFIX) {
        Ok(log) => Some(log),
        Err(err) => {
            eprintln!("не удалось открыть файл журнала: {err}");
            None
        }
    }
}

fn install<W>(writer: W, ansi: bool, verbose: bool)
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter(verbose))
        .with_target(false)
        .with_ansi(ansi)
        .with_writer(writer)
        .with_filter_reloading();
    let handle = builder.reload_handle();

    if builder.try_init().is_ok() && !pinned(verbose) {
        let _ = RELOAD.set(Box::new(move |filter| {
            if let Err(err) = handle.reload(filter) {
                eprintln!("уровень журнала не изменён: {err}");
            }
        }));
    }
}

/// `RUST_LOG` сильнее флага: тому, кто его выставил, виднее.
fn filter(verbose: bool) -> EnvFilter {
    let default = if verbose { "debug" } else { "info" };
    EnvFilter::try_from_default_env().unwrap_or_else(|_| level_filter(default))
}

fn level_filter(level: &str) -> EnvFilter {
    EnvFilter::new(format!("penguin={level},warn"))
}

/// Уровень задан руками и настройкой не двигается.
fn pinned(verbose: bool) -> bool {
    verbose || EnvFilter::try_from_default_env().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_defaults_to_info() {
        assert!(filter(false).to_string().contains("info"));
        assert!(filter(true).to_string().contains("debug"));
    }

    #[test]
    fn missing_directory_does_not_stop_the_daemon() {
        // Родитель — обычный файл: каталог завести нельзя.
        let file = std::env::temp_dir().join(format!("penguin-{}-file", std::process::id()));
        std::fs::write(&file, b"x").expect("файл пишется");
        let directory = file.join("logs");

        init_file(&directory, false);
        assert!(open_log(&directory).is_none());
        std::fs::remove_file(&file).expect("файл убирается");
    }

    #[cfg(unix)]
    #[test]
    fn an_unwritable_directory_does_not_stop_the_daemon() {
        use std::os::unix::fs::PermissionsExt;

        // Общий каталог службы без прав записи: каталог есть, писать некуда.
        let directory = std::env::temp_dir().join(format!("penguin-{}-ro", std::process::id()));
        std::fs::create_dir_all(&directory).expect("каталог заводится");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o555))
            .expect("права ставятся");

        let unwritable = std::fs::File::create(directory.join("проба")).is_err();
        let log = open_log(&directory);
        // Под `root` права ничего не запрещают; главное — не упасть.
        if unwritable {
            assert!(log.is_none(), "журнала быть не может, а падать нельзя");
        }

        drop(log);
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
            .expect("права возвращаются");
        std::fs::remove_dir_all(&directory).expect("каталог убирается");
    }

    #[test]
    fn the_daemon_and_the_window_do_not_share_a_log() {
        assert_ne!(PREFIX, "gui.log");
    }
}
