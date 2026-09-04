//! Куда пишет журнал — зависит от того, кем программа запустилась.
//!
//! Три роли, три разных ответа, и подменять один другим нельзя:
//!
//! - **терминал** пишет в поток ошибок. В поток вывода идёт результат
//!   команды, и смешивать их нельзя — `--json` перестал бы разбираться;
//! - **служба** пишет в файл. Терминала у неё нет, всё напечатанное исчезает,
//!   и файл — единственный источник сведений о том, что происходило;
//! - **окно** тоже пишет в файл, но в свой. Смешать их значит потерять ответ
//!   на вопрос «кто это сделал, окно или служба».

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

use crate::args::{Cli, Command};

/// Начало имени файла журнала окна.
const GUI_PREFIX: &str = "gui.log";

/// Настраивает журнал под роль этого запуска.
///
/// Возвращает страж, который надо держать живым: запись в файл идёт из
/// отдельного потока, и с уничтожением стража она прекращается.
pub fn init(cli: &Cli) -> Option<WorkerGuard> {
    let filter = filter(cli.verbose);

    // Служба заводит журнал сама: ей нужен свой файл и своя уборка старых
    // частей, и делает она это внутри своей точки входа.
    if cli.service {
        return None;
    }

    if cli.command.is_some() || cli.foreground {
        // Терминал: в поток ошибок, чтобы не мешать результату команды.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_target(false)
            .try_init();
        return None;
    }

    to_file(filter)
}

/// Журнал окна — в файл в профиле пользователя.
///
/// Не `discover`, а именно профиль. Общий каталог принадлежит `root`: его
/// заводит установка службы, и пользователю он открыт только на чтение. Окно
/// же всегда работает от пользователя, и «рядом с журналом службы» для него
/// означало бы «никуда» — на любой машине, где службу поставили.
fn to_file(filter: EnvFilter) -> Option<WorkerGuard> {
    let directory = penguin_config::Paths::user()
        .ok()
        .map(|paths| paths.data_dir().to_path_buf())
        .filter(|directory| std::fs::create_dir_all(directory).is_ok())?;

    // `tracing_appender` разбивает журнал по дням, но старые части не убирает.
    penguin_config::logs::prune(&directory, GUI_PREFIX, penguin_config::logs::KEEP_FILES);

    // Через билдер, а не `rolling::daily`: та на отказ не возвращает ошибку, а
    // паникует, и окно падало бы вместо того, чтобы открыться без журнала.
    // Проверки каталога выше для этого мало — она проходит и для чужого
    // каталога, в который потом не пускают.
    let appender = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix(GUI_PREFIX)
        .build(&directory)
        .ok()?;

    let (writer, guard) = tracing_appender::non_blocking(appender);

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        // Цвет в файле превращается в управляющие последовательности, и читать
        // его потом невозможно.
        .with_ansi(false)
        .with_writer(writer)
        .try_init();

    Some(guard)
}

/// Собирает фильтр уровней.
///
/// `RUST_LOG` сильнее флага: тому, кто его выставил, виднее.
fn filter(verbose: bool) -> EnvFilter {
    let default = if verbose { "debug" } else { "info" };
    EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("penguin={default},warn")))
}

/// Роль запуска — только для читаемости соседнего кода.
#[allow(dead_code, reason = "используется тестами ниже как описание намерения")]
fn is_terminal(cli: &Cli) -> bool {
    matches!(cli.command, Some(Command::Client(_) | Command::Service(_))) || cli.foreground
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    fn cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("разбирается")
    }

    #[test]
    fn the_verbose_flag_changes_the_level() {
        assert!(filter(false).to_string().contains("info"));
        assert!(filter(true).to_string().contains("debug"));
    }

    #[test]
    fn terminal_roles_write_to_the_error_stream() {
        // В поток вывода идёт результат команды: смешать их значит сломать
        // `--json`.
        assert!(is_terminal(&cli(&["penguin", "doctor"])));
        assert!(is_terminal(&cli(&["penguin", "service", "status"])));
        assert!(is_terminal(&cli(&["penguin", "--foreground"])));
    }

    #[test]
    fn the_window_does_not_write_to_a_terminal_it_does_not_have() {
        assert!(!is_terminal(&cli(&["penguin"])));
    }

    #[test]
    fn the_window_and_the_service_keep_separate_files() {
        // Смешать их значит потерять ответ на вопрос «кто это сделал».
        assert_ne!(GUI_PREFIX, "penguin.log");
    }
}
