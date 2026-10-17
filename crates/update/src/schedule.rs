//! Когда проверять обновления в следующий раз.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Не чаще раза в это число секунд (12 часов): лимит GitHub API без токена — 60 запросов в час.
pub const INTERVAL_SECS: u64 = 12 * 60 * 60;

/// Пора ли проверять; `None` — не проверяли никогда. Часы, ушедшие назад, — тоже пора.
pub fn is_due(last: Option<u64>, now: u64) -> bool {
    last.is_none_or(|last| now < last || now - last >= INTERVAL_SECS)
}

/// Секунды Unix сейчас.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Когда проверяли последний раз; нет файла или он неразборчив — `None`.
pub fn last_check(file: &Path) -> Option<u64> {
    std::fs::read_to_string(file).ok()?.trim().parse().ok()
}

/// Запоминает проверку в `file`.
pub fn mark_checked(file: &Path, now: u64) -> std::io::Result<()> {
    if let Some(directory) = file.parent() {
        std::fs::create_dir_all(directory)?;
    }
    std::fs::write(file, now.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_checked_is_due() {
        assert!(is_due(None, 1_000));
    }

    #[test]
    fn due_only_after_the_interval() {
        let last = 1_000_000;
        assert!(!is_due(Some(last), last));
        assert!(!is_due(Some(last), last + INTERVAL_SECS - 1));
        assert!(is_due(Some(last), last + INTERVAL_SECS));
    }

    #[test]
    fn a_clock_set_back_does_not_silence_checks() {
        assert!(is_due(Some(2_000_000), 1_000_000));
    }

    #[test]
    fn the_stamp_survives_a_round_trip_and_garbage_is_none() {
        let directory =
            std::env::temp_dir().join(format!("penguin-schedule-{}", std::process::id()));
        let file = directory.join("nested").join("update-check");

        assert_eq!(last_check(&file), None);
        mark_checked(&file, 1234).expect("запись");
        assert_eq!(last_check(&file), Some(1234));

        std::fs::write(&file, "мусор").expect("запись");
        assert_eq!(last_check(&file), None);
        std::fs::remove_dir_all(&directory).expect("уборка");
    }
}
