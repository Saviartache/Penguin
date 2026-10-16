//! Файл журнала с суточной ротацией и уборкой старых частей.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Сколько частей журнала хранить (неделя при ежедневной разбивке).
pub const KEEP_FILES: usize = 7;

/// Журнал `<prefix>.ГГГГ-ММ-ДД` (UTC): новый файл на каждые сутки.
///
/// Запись идёт сразу в файл, без буфера: при падении теряется не больше одной строки.
#[derive(Debug)]
pub struct DailyLog {
    directory: PathBuf,
    prefix: String,
    day: u64,
    file: File,
}

impl DailyLog {
    /// Открывает файл за сегодня и убирает старые части.
    pub fn open(directory: &Path, prefix: &str) -> io::Result<Self> {
        let day = today();
        let file = open_day(directory, prefix, day)?;
        prune(directory, prefix, KEEP_FILES);
        Ok(Self {
            directory: directory.to_path_buf(),
            prefix: prefix.to_owned(),
            day,
            file,
        })
    }

    /// Переходит на новый файл, если наступили новые сутки; при отказе пишет в старый.
    fn roll(&mut self) {
        let day = today();
        if day == self.day {
            return;
        }
        if let Ok(file) = open_day(&self.directory, &self.prefix, day) {
            self.file = file;
            self.day = day;
            prune(&self.directory, &self.prefix, KEEP_FILES);
        }
    }
}

impl Write for DailyLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.roll();
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// Номер суток от начала эпохи.
fn today() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() / 86_400)
}

fn open_day(directory: &Path, prefix: &str, day: u64) -> io::Result<File> {
    let (year, month, date) = civil_from_days(day);
    let name = format!("{prefix}.{year:04}-{month:02}-{date:02}");
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join(name))
}

/// Дата по числу суток с 1970-01-01 (алгоритм Хиннанта).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let date = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, date)
}

/// Убирает старые части журнала, оставляя `keep` самых свежих.
///
/// Сортировка по имени (`penguin.log.2026-09-01`); файл без даты не трогается.
/// Ошибки игнорируются.
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

    /// Каталог с частями журнала за перечисленные дни.
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
    fn civil_dates_match_known_days() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(20_742), (2026, 10, 16));
        assert_eq!(civil_from_days(19_722), (2023, 12, 31));
    }

    #[test]
    fn daily_log_appends_to_a_dated_file() {
        let dir = log_dir("daily", &[]);
        let mut log = DailyLog::open(&dir, PREFIX).expect("журнал открывается");
        log.write_all(b"one\n").expect("пишется");
        drop(log);
        let mut log = DailyLog::open(&dir, PREFIX).expect("журнал открывается");
        log.write_all(b"two\n").expect("пишется");

        let (year, month, date) = civil_from_days(today());
        let path = dir.join(format!("{PREFIX}.{year:04}-{month:02}-{date:02}"));
        assert_eq!(std::fs::read(path).expect("файл есть"), b"one\ntwo\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daily_log_prunes_old_parts_on_open() {
        let days: Vec<String> = (1..=10).map(|day| format!("2020-01-{day:02}")).collect();
        let names: Vec<&str> = days.iter().map(String::as_str).collect();
        let dir = log_dir("daily-prune", &names);
        let _log = DailyLog::open(&dir, PREFIX).expect("журнал открывается");
        assert_eq!(
            std::fs::read_dir(&dir).expect("каталог читается").count(),
            KEEP_FILES
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keeps_a_reasonable_number_of_files() {
        const { assert!(KEEP_FILES >= 3 && KEEP_FILES <= 30) };
    }

    #[test]
    fn pruning_keeps_the_newest_parts() {
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
        let dir = log_dir("today", &[]);
        std::fs::write(dir.join(PREFIX), b"x").expect("файл пишется");

        prune(&dir, PREFIX, 0);
        assert!(dir.join(PREFIX).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pruning_touches_only_its_own_prefix() {
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
        prune(Path::new("нет такого каталога"), PREFIX, 1);
    }
}
