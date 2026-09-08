//! Журналирование в файл с ротацией.
//!
//! У службы нет терминала: всё, что она печатает, исчезает. Поэтому журнал
//! пишется в файл — и это единственный источник сведений о том, что
//! происходило, когда пользователь придёт с вопросом «не работает».
//!
//! Ротация обязательна. Журнал уровня `debug` на активном тоннеле растёт
//! мегабайтами в час, а служба работает месяцами.

use std::path::Path;
use std::sync::OnceLock;

use penguin_config::schema::app::LogLevel;
use tracing_subscriber::EnvFilter;

/// Начало имени файла журнала; дату к нему приписывает `tracing_appender`.
///
/// Своё у каждой программы: журналы службы и окна могут оказаться в одном
/// каталоге, и уборка одного не должна задевать другой.
const PREFIX: &str = "penguin.log";

/// Чем менять уровень уже заведённого журнала.
///
/// Журнал заводится раньше, чем прочитаны настройки: у службы нет терминала,
/// и отказ на чтении настроек тоже надо куда-то записать. Поэтому уровень из
/// настроек доводится сюда потом — [`set_level`].
static RELOAD: OnceLock<Box<dyn Fn(EnvFilter) + Send + Sync>> = OnceLock::new();

/// Настраивает журнал в терминал.
///
/// Так демон запускают при отладке.
pub fn init_console(verbose: bool) {
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter(verbose))
        .with_target(false)
        .with_filter_reloading();
    let handle = builder.reload_handle();

    if builder.try_init().is_ok() {
        remember(handle, verbose);
    }
}

/// Меняет уровень журнала на работающей службе.
///
/// Флаг `--verbose` и `RUST_LOG` сильнее настройки: тот, кто попросил
/// подробностей руками, не должен терять их от переключателя в окне.
pub fn set_level(level: LogLevel) {
    if let Some(reload) = RELOAD.get() {
        reload(level_filter(level.as_str()));
    }
}

/// Запоминает, чем менять уровень.
fn remember<S>(handle: tracing_subscriber::reload::Handle<EnvFilter, S>, verbose: bool)
where
    S: 'static,
{
    if pinned(verbose) {
        return;
    }
    let _ = RELOAD.set(Box::new(move |filter| {
        if let Err(err) = handle.reload(filter) {
            eprintln!("уровень журнала не изменён: {err}");
        }
    }));
}

/// Настраивает журнал в файл.
///
/// Возвращает страж, который надо держать живым: запись идёт из отдельного
/// потока, и с уничтожением стража она прекращается.
pub fn init_file(
    directory: &Path,
    verbose: bool,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    if let Err(err) = std::fs::create_dir_all(directory) {
        // Журнала не будет, но служба обязана подняться: без журнала она
        // работает, без службы — нет.
        eprintln!("не удалось создать каталог журнала: {err}");
        return None;
    }

    // До того, как открыть новый файл: `tracing_appender` умеет разбивать
    // журнал по дням, но не умеет убирать старые части, а служба работает
    // месяцами.
    penguin_config::logs::prune(directory, PREFIX, penguin_config::logs::KEEP_FILES);

    // Через билдер, а не `rolling::daily`: та на отказ не возвращает ошибку, а
    // паникует. Каталог мог создаться и всё же не пустить — например, когда
    // демона подняли на переднем плане не от администратора, — и служба обязана
    // подняться без журнала, а не упасть вместе с ним.
    let appender = match tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix(PREFIX)
        .build(directory)
    {
        Ok(appender) => appender,
        Err(err) => {
            eprintln!("не удалось открыть файл журнала: {err}");
            return None;
        }
    };

    let (writer, guard) = tracing_appender::non_blocking(appender);

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter(verbose))
        .with_target(false)
        // Цвет в файле превращается в управляющие последовательности, и
        // читать его потом невозможно.
        .with_ansi(false)
        .with_writer(writer)
        .with_filter_reloading();
    let handle = builder.reload_handle();

    if builder.try_init().is_ok() {
        remember(handle, verbose);
    }

    Some(guard)
}

/// Собирает фильтр уровней.
fn filter(verbose: bool) -> EnvFilter {
    let default = if verbose { "debug" } else { "info" };
    // `RUST_LOG` сильнее флага: тому, кто его выставил, виднее.
    EnvFilter::try_from_default_env().unwrap_or_else(|_| level_filter(default))
}

/// Фильтр одного уровня.
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
        // Уровень `debug` на активном тоннеле пишет мегабайты в час.
        assert!(filter(false).to_string().contains("info"));
        assert!(filter(true).to_string().contains("debug"));
    }

    #[test]
    fn missing_directory_does_not_stop_the_daemon() {
        // Без журнала служба работает; без службы — нет.
        let path = std::path::Path::new("");
        let guard = init_file(path, false);
        drop(guard);
    }

    #[cfg(unix)]
    #[test]
    fn an_unwritable_directory_does_not_stop_the_daemon() {
        use std::os::unix::fs::PermissionsExt;

        // Так выглядит общий каталог, заведённый установкой службы, когда
        // демона подняли на переднем плане не от администратора: каталог есть,
        // права `create_dir_all` не трогает, а записи в нём нет. На этом месте
        // `rolling::daily` паниковала, и программа падала вместо того, чтобы
        // работать без журнала.
        let directory = std::env::temp_dir().join(format!("penguin-{}-ro", std::process::id()));
        std::fs::create_dir_all(&directory).expect("каталог заводится");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o555))
            .expect("права ставятся");

        let unwritable = std::fs::File::create(directory.join("проба")).is_err();

        let guard = init_file(&directory, false);
        // Под `root` права каталога не запрещают ничего, и проверять нечего —
        // но дойти до сюда, не упав, обязаны обе учётные записи.
        if unwritable {
            assert!(guard.is_none(), "журнала быть не может, а падать нельзя");
        }

        drop(guard);
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
            .expect("права возвращаются");
        std::fs::remove_dir_all(&directory).expect("каталог убирается");
    }

    #[test]
    fn the_daemon_and_the_window_do_not_share_a_log() {
        // Журналы лежат в одном каталоге, и общее начало имени означало бы,
        // что уборка одного стирает части другого.
        assert_ne!(PREFIX, "gui.log");
    }
}
