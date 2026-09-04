//! Журналирование в файл с ротацией.
//!
//! У службы нет терминала: всё, что она печатает, исчезает. Поэтому журнал
//! пишется в файл — и это единственный источник сведений о том, что
//! происходило, когда пользователь придёт с вопросом «не работает».
//!
//! Ротация обязательна. Журнал уровня `debug` на активном тоннеле растёт
//! мегабайтами в час, а служба работает месяцами.

use std::path::Path;

use tracing_subscriber::EnvFilter;

/// Начало имени файла журнала; дату к нему приписывает `tracing_appender`.
///
/// Своё у каждой программы: журналы службы и окна могут оказаться в одном
/// каталоге, и уборка одного не должна задевать другой.
const PREFIX: &str = "penguin.log";

/// Настраивает журнал в терминал.
///
/// Так демон запускают при отладке.
pub fn init_console(verbose: bool) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter(verbose))
        .with_target(false)
        .try_init();
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

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter(verbose))
        .with_target(false)
        // Цвет в файле превращается в управляющие последовательности, и
        // читать его потом невозможно.
        .with_ansi(false)
        .with_writer(writer)
        .try_init();

    Some(guard)
}

/// Собирает фильтр уровней.
fn filter(verbose: bool) -> EnvFilter {
    let default = if verbose { "debug" } else { "info" };
    // `RUST_LOG` сильнее флага: тому, кто его выставил, виднее.
    EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("penguin={default},warn")))
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
