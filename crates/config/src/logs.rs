//! Уборка старых частей журнала.
//!
//! Здесь, а не в демоне, потому что журналов два: демон пишет `penguin.log`,
//! окно — `gui.log`, оба в один каталог, и растут оба. Уборка, живущая в
//! одном из них, — это второй журнал, который никто не убирает.
//!
//! Почему уборка вообще нужна: `tracing_appender` умеет разбивать журнал по
//! дням, но не умеет удалять старые части. Клиент работает месяцами, а журнал
//! уровня `debug` на активном тоннеле растёт мегабайтами в час.

use std::path::{Path, PathBuf};

/// Сколько частей журнала хранить.
///
/// Неделя при ежедневной разбивке — достаточно, чтобы разобрать вчерашнюю
/// неполадку, и мало, чтобы заметить по месту на диске.
pub const KEEP_FILES: usize = 7;

/// Убирает старые части журнала, оставляя `keep` самых свежих.
///
/// Отбор идёт по имени файла, а не по времени изменения: `tracing_appender`
/// приписывает к имени дату (`penguin.log.2026-09-01`), и она сортируется как
/// строка. Время изменения соврало бы после копирования каталога.
///
/// Сегодняшний файл — тот, что без даты, — не трогается ни при каком `keep`:
/// убрать его значило бы стереть журнал того самого запуска, который сейчас и
/// разбирают.
///
/// Ошибки молча пропускаются: невозможность убрать старый файл — не повод не
/// запуститься.
pub fn prune(directory: &Path, prefix: &str, keep: usize) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };

    let mut parts: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix) && name.len() > prefix.len())
        })
        .collect();

    if parts.len() <= keep {
        return;
    }

    parts.sort();
    let doomed = parts.len() - keep;
    for path in parts.into_iter().take(doomed) {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "penguin.log";

    /// Каталог с готовыми частями журнала за перечисленные дни.
    ///
    /// Имя с меткой и номером процесса: тесты идут в общем временном каталоге
    /// и параллельно, а общий каталог на всех — это тест, который падает через
    /// раз и не воспроизводится.
    fn log_dir(tag: &str, days: &[&str]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("penguin-log-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("каталог создаётся");

        for day in days {
            std::fs::write(dir.join(format!("{PREFIX}.{day}")), b"x")
                .expect("часть журнала пишется");
        }
        dir
    }

    #[test]
    fn keeps_a_reasonable_number_of_files() {
        const { assert!(KEEP_FILES >= 3 && KEEP_FILES <= 30) };
    }

    #[test]
    fn pruning_keeps_the_newest_parts() {
        // Клиент работает месяцами: без уборки журнал растёт, пока не кончится
        // место.
        let dir = log_dir(
            "newest",
            &["2026-08-28", "2026-08-29", "2026-08-30", "2026-08-31"],
        );
        prune(&dir, PREFIX, 2);

        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .expect("каталог читается")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();

        assert_eq!(
            left,
            [
                format!("{PREFIX}.2026-08-30"),
                format!("{PREFIX}.2026-08-31")
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pruning_leaves_todays_file_alone() {
        // Сегодняшний файл идёт без даты в имени, и убрать его значило бы
        // стереть журнал того самого запуска, который сейчас разбирают.
        let dir = log_dir("today", &[]);
        std::fs::write(dir.join(PREFIX), b"x").expect("файл пишется");

        prune(&dir, PREFIX, 0);
        assert!(dir.join(PREFIX).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pruning_touches_only_its_own_prefix() {
        // В одном каталоге лежат журналы службы и окна; уборка одного не
        // должна задевать другой.
        let dir = log_dir("prefix", &["2026-08-28", "2026-08-29", "2026-08-30"]);
        std::fs::write(dir.join("gui.log.2026-08-28"), b"x").expect("файл пишется");

        prune(&dir, PREFIX, 1);

        assert!(
            dir.join("gui.log.2026-08-28").exists(),
            "задет чужой журнал"
        );
        assert!(dir.join(format!("{PREFIX}.2026-08-30")).exists());
        assert!(!dir.join(format!("{PREFIX}.2026-08-28")).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pruning_a_short_history_changes_nothing() {
        let dir = log_dir("short", &["2026-08-30", "2026-08-31"]);
        prune(&dir, PREFIX, KEEP_FILES);

        assert_eq!(
            std::fs::read_dir(&dir).expect("каталог читается").count(),
            2
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pruning_a_missing_directory_is_not_an_error() {
        // Невозможность убрать старый файл — не повод не запуститься.
        prune(Path::new("нет такого каталога"), PREFIX, 1);
    }
}
